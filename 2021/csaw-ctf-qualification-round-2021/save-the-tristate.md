---
description: Quantum Key Distribution (QKD)
---

# Save the Tristate

## Description

So it was just another day in Danville when Phineas and Ferb were making a new device to communicate with Meep as he travels across the galaxy. To make a device suitable for galatic communication and secure enough to be safe from alien hackers, they decide to protect their device with QKD! Unfortunately, due to Phineas & Co singing their usual musical numbers about their inventions, Doofenshmirtz has caught wind of this technology and wants to use it to take over the Tristate area, using his brand new Qubit-Disrupt-inator. Naturally I, Major Monogram, have to send you, Perry the Platypus, on a mission to stop Doofenshmirtz from disrupting Phineas and Ferb's qubits with his diabolical inator. So grab your tiny fedora and doo-bee-doo-bee-doo-ba-doo your way over to stop Doofenshmirtz! Mission:

* Receive \# of qubits that translate to the flag
* Measure qubits in your own basis
* Monogram tells you how many qubits were measured correctly, but not which ones
* Go back and fix it
* Get it right

nc misc.chal.csaw.io 5001

## Solution

### BB84

To solve this challenge, one has to understand the BB84 protocol. 

Alice and Bob want to share a secret key over a potentially insecure channel.

1. Alice generates N bits and N bases \(either `+` or `x`\). She encodes the generated bits as qubits in the bases she has chosen.
2. Bob also randomly chooses N bases. He reads the qubits sent by Alice and measures them using the bases he generated. Note that Bob has a 50% chance of generating the same basis as Alice for each bit - otherwise, Bob will measure the bits wrongly.
3. Alice and Bob share their basis with each other and get rid of every bit that was measured by different bases.

Note that at this point, Bob and Alice would share a common secret, which is the sequence of bits that were measured correctly with the same basis. They can then verify part of the shared bits with each other. 

This method is secure, because if an eavesdropper, Eve, had interfered with the quantum channel, then Alice and Bob will disagree on the "verification bits" and Eve would be unveiled.

### Bruteforcing the Basis

This challenge is a little different, though. The server tells us _how many_ basis we got right, but not _which ones_. We can simply bruteforce this, though, by making sure that the number of errors remains at 0.

```python
from pwn import *
from Crypto.Util.number import *

conn = remote("misc.chal.csaw.io", 5001)

length = 1
curr = ''
prev_checked = '+'

print(conn.recvuntil(b"? \r\n").decode())

while True:    
    conn.sendline((str(length)).encode())
    print(conn.recvuntil(b": \r\n").decode())

    if prev_checked == '+':
        to_check = 'x'
    else:
        to_check = '+'
    
    prev_checked = to_check

    conn.sendline((curr + to_check).encode())

    if length != 256:
        received = conn.recvuntil(b"? \r\n").decode()
    else:
        received = conn.recv().decode()
    
    print(received)

    if 'Errors: 0' in received:
        curr += to_check
        length += 1

        print("Current:", curr)

        if length > 256:
            break
```

### Getting the Key

After we get all 256 basis right, we are given the measured qubits. Note that at this point, we  share the same basis as the server, so all of the bits will be used as part of the key. We simply have to decode the bit values, based on the basis of each bit, to get the key.

![](../../.gitbook/assets/image%20%2877%29.png)

Adding on to the script above:

```python
data = received
data += conn.recvuntil("What is the key?").decode()
print(data)

key = 0
for line in data.splitlines():
    
    # 0 + 1i
    if line.startswith('0.0'):
        key *= 2
        key += 1
    
    # 1 + 0i
    elif line.startswith('1.0'):
        key *= 2
        key += 0
    
    # 0.707 + 0.707i
    elif line.startswith('0.707'):
        key *= 2
        key += 0
    
    # -0.707 + 0.707i
    elif line.startswith('-0.707'):
        key *= 2
        key += 1

    elif line.startswith("What is the key?"):
        break

    else:
        pass

print(bin(key))
print(str(key))

conn.interactive()
```

It turns out the key is a string. Submit the key to get the flag!

```python
>>> long_to_bytes(43931681853956549478184553086187289692451455473923533011002686733443258084897)
b'a semi-aquatic mammal of action!'
```

The flag is `flag{MO0O0O0O0M PH1NE4S & F3RB R T4LK1NG 2 AL1ENS 0V3R QKD!!!}`

## References

* [https://devel0pment.de/?p=1533](https://devel0pment.de/?p=1533)
* [https://ctftime.org/writeup/18212](https://ctftime.org/writeup/18212)

