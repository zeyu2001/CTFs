# Level 2 - Leaky Matrices

## Description

> Looks like PALINDROME implemented their own authentication protocol and cryptosystem to provide a secure handshake between any 2 services or devices. It does not look secure to us, can you take a look at what we have got?
>
> Try to fool their authentication service: nc chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg 56765

{% file src="../../.gitbook/assets/2WKV_Whitepaper.pdf" %}

## Solution

This was a pretty straightforward crypto challenge where a weak authentication scheme allowed the leaking of the secret key through a challenge-response sequence. This relied on the following matrix multiplication in $$GF(2)$$.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-12 at 1.36.22 AM.png" alt=""><figcaption></figcaption></figure>

Importantly, this is equivalent to

$$
c_1
\begin{bmatrix}
	s_{11} \\
	s_{21} \\
	\vdots \\
	s_{n1}
\end{bmatrix}
+
c_2
\begin{bmatrix}
	s_{12} \\
	s_{22} \\
	\vdots \\
	s_{n2}
\end{bmatrix}
+
\cdots
c_n
\begin{bmatrix}
	s_{1n} \\
	s_{2n} \\
	\vdots \\
	s_{nn}
\end{bmatrix}
=
\begin{bmatrix}
	c_{1}s_{11} + c_{2}s_{12} + \cdots + c_{n}s_{1n} \\
	c_{1}s_{21} + c_{2}s_{22} + \cdots + c_{n}s_{2n} \\
	\vdots \\
	c_{1}s_{n1} + c_{2}s_{n2} + \cdots + c_{n}s_{nn}
\end{bmatrix}
$$

​Since we control the challenge bits _c_, we could leak the result of each column by challenging the server. For example, setting $$c_1=1, c_{2 ... n}=0$$ gives us

$$
\begin{bmatrix} 	r_1 \\ 	r_2 \\ 	\vdots \\ 	r_n \end{bmatrix} = \begin{bmatrix} 	c_{1}s_{11} \\ 	c_{1}s_{21} \\ 	\vdots \\ 	c_{1}s_{n1} \end{bmatrix}
$$

​and since we can do the same for all $$c_{1...n}$$, we could reconstruct the response to any challenge by adding up the relevant column results.

The solution to this challenge is to simply probe the server with `00000001`, `00000010`, ... `10000000`, and when challenged, take the 1-bits and add up their corresponding probed values.

Since this happens in $$GF(2)$$, addition is the same as XOR (hence the use of XOR in the script).

```python
from pwn import *
import re

conn = remote("chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg", 56765)

def solve():
    rows = []
    for i in range(8):
        conn.recvuntil(b"<-- ")
        binstr = "0" * (8 - i - 1) + "1" + "0" * (i)
        conn.send(binstr.encode() + b"\n")
        resp = conn.recvline().decode()
        match = re.search(r"--> (.*)\n", resp)
        
        rows.append(int(match.group(1), 2))
    
    for i in range(8):
        resp = conn.recvuntil(b"<-- ").decode()
        match = re.search(r"--> (.*)\n", resp)

        challenge = match.group(1)
        result = 0
        for j in range(8):
            if challenge[j] == "1":
                result ^= rows[7 - j]

        conn.send(bin(result)[2:].zfill(8).encode() + b"\n")
    
    conn.interactive()

solve()
```

This gives us the flag.

```
========================
All challenges passed :)
========================
=================================================================
Here is your flag: TISC{d0N7_R0lL_Ur_0wN_cRyp70_7a25ee4d777cc6e9}
=================================================================
```
