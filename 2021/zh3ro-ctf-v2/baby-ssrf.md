---
description: >-
  SSRF blacklist bypass enabled internal port scan and access to hidden
  endpoints.
---

# Baby SSRF

## Problem

Yet another server challenge :)

### Hint

for i in range(5000,10000)

xD

## Solution

We are given a `/request` endpoint from which we are able to submit a URL. 

If the host is not found or the URL is invalid, `Learn about URL&#39;s First` is returned.

If SSRF is detected, `Please dont try to heck me sir...` is returned. This was blacklist based, as pretty much every site is allowed except for `localhost` and anything containing the numbers `127`.

Otherwise, the HTTP response headers are returned.

My teammate rainbowpigeon found that the server was using Python's requests library to issue GET requests to the submitted URL, and returning `r.headers`.

![](<../../.gitbook/assets/image (9).png>)

I found that we could bypass the localhost blacklist using something like `url=http://0177.0.0.1:9006/&sub=sub`. In most cases, `0177.0.0.1` will resolve to `127.0.0.1`. We can even see this behaviour in Chrome:

![](<../../.gitbook/assets/Screenshot 2021-06-07 at 1.17.16 AM.png>)

Once we bypass this filter, we could perform an internal port scan by e.g. writing a simple Python script or using Burp Intruder. From the hint, we know that we are looking for a port between 5000 and 10000.

This allows us to find ports that are not publicly accessible, but only accessible through the local machine itself. We found that ports 8080 and 9006 were open.

Since we only get the headers in the response, we don't have much to go off on except for things like the `Content-Length` header. Not Found (404) pages would have the same content length, so a different content length indicates that the page exists.

For localhost:8080, we find the `/request` endpoint. This means that the page at port 8080 is the same as the public challenge site.

![](<../../.gitbook/assets/image (10).png>)

The only remaining port would be 9006. Directly accessing it through `http://0177.0.0.1:9006/` did not give us anything meaningful, but a redirection through our PHP server revealed the flag in one of the headers.

Since the Python requests library follows redirections, our PHP server hosts the following:

```php
<?php
    header("Location: http://localhost:9006/");
?>
```

This reveals the flag:

![](<../../.gitbook/assets/image (8).png>)



