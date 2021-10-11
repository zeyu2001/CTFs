---
description: RSA Chosen Ciphertext Attack
---

# Rocket Ship Academy

## Description

Oracle: a person or thing regarded as an infallible authority on something.

Do we have one of those here?

`nc 20.198.209.142 55002`

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

## Solution

We are given an RSA decryption oracle. We can supply any ciphertext to be decrypted, except the original, given ciphertext.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 6.00.10 PM.png>)

Textbook RSA is vulnerable to Chosen Ciphertext Attack (CCA), where a user is able to supply an arbitrary ciphertext to be decrypted.

Recall that

$$
ed\equiv1\pmod{(p-1)(q-1)}
$$

Therefore, suppose we supply a ciphertext

$$
c'=r^ec\pmod{n}
$$

then decrypting this gives

$$
m'=r^{ed}c^d\pmod{n}\newline
m'=rm\pmod{n}
$$

Let $$r=2$$ . The solve script is as follows:

```python
from Crypto.Util.number import long_to_bytes
from pwn import *
from decimal import *
import re

getcontext().prec = 100000000

pattern = "n = (\d+)\ne = (\d+)\nc = (\d+)"

conn = remote('localhost', '12345')
received = conn.recv().decode()

matches = re.search(pattern, received)
n, e, c = int(matches[1]), int(matches[2]), int(matches[3])

print('n =', n)
print('e =', e)
print('c =', c)
print()

ciphertext = Decimal(c) * ((2 ** Decimal(e)) % Decimal(n)) % Decimal(n)
print('Ciphertext:', ciphertext)

conn.send(str(ciphertext) + '\r\n')

received = conn.recv().decode()
matches = re.search("Decrypted: (\d+)\n", received)

decrypted = int(matches[1])
print()

print(long_to_bytes(Decimal(decrypted) / 2))
```

The flag is `STC{ch0s3n_c1ph3rt3xt_d7b593cd54baba9e2ffa49215d33e4c657cf230a}`.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 6.59.38 PM.png>)
