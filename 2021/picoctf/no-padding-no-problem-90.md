---
description: RSA chosen-ciphertext attack (CCA)
---

# No Padding, No Problem \(90\)

## Problem

Oracles can be your best friend, they will decrypt anything, except the flag's ciphertext. How will you break it? Connect with `nc mercury.picoctf.net 30048`.

## Solution

This is a chosen-ciphertext attack \(CCA\) against RSA. We are able to choose any ciphertext, except the flag's ciphertext, to decrypt.

TL;DR: we can use $$c'=c * 2^e$$ as the ciphertext, then halve the result.

### Proof

Note that:

1. $$c^d \equiv m \pmod n$$ 
2. $$d$$ is chosen such that $$ed \equiv 1 \pmod {\phi(n)}$$, i.e. $$ed=1 + k\phi(n), k\in \mathbb{N_0}$$.

The decryption of $$c'$$ would yield:

$$
\begin{align}

(c * 2^e)^d \mod n &\equiv c^d * 2^{ed} \mod n \\
&\equiv (c^d \mod n)(2^{ed} \mod n) \mod n \\
&\equiv m * (2^{1+k\phi(n)} \mod n) \mod n \\
&\equiv m * 2 * (2^{k\phi(n)} \mod n) \mod n \\

\end{align}
$$

From Euler's Theorem, if $$gcd(a,n)=1$$ , then

$$
a^{\phi(n)} \equiv 1\pmod n
$$

Thus, we have

$$
m * 2 * (2^{k\phi(n)} \mod n) \mod n \equiv 2m \mod n
$$

At this point, we can halve the result to get $$m$$ .

### Script

```python
from Crypto.Util.number import *
from pwn import *
from decimal import *
import re

getcontext().prec = 1000

conn = remote('mercury.picoctf.net', 30048)
raw_text = conn.recvuntil('Give me ciphertext to decrypt:').decode()

print(raw_text)

m = re.search(r"n: ([0-9]+)\ne: ([0-9]+)\nciphertext: ([0-9]+)", raw_text)
n = int(m[1])
e = int(m[2])
c = int(m[3])

to_decrypt = c * pow(2, e, n) % n

conn.send(str(to_decrypt) + '\r\n')

print("Sent:", to_decrypt)

result = conn.recvline().decode()

print(result)

m = re.search(r"([0-9]+)", result)
result = int(Decimal(m[1]) / 2)

print(hex(result))
print('Result:', long_to_bytes(result))
```

## References

1. [https://cseweb.ucsd.edu/classes/sp20/cse291-i/lectures/11-rsa2-notes.pdf](https://cseweb.ucsd.edu/classes/sp20/cse291-i/lectures/11-rsa2-notes.pdf)

