# Personal Encryptor with Nonbreakable Inforation-theoretic Security

## Description

> The Personal Encryptor with Nonbreakable Information-theoretic Security seems rock solid.
>
> `nc challs.rumble.host 17171`
>
> The PoC's code is even available.

{% file src="../../.gitbook/assets/Personal_Encryptor_with_Nonbreakable_Information-theoretic_Security.tar.gz" %}

## Solution

The encryption algorithm generates random bytes using `os.urandom()` and adds them to the position of the original character in the 63-character alphabet. Every 63 characters “wraps around” back to the original character.

```python
def keygen(length):
    key = ""
    rnd_bytes = os.urandom(length)
    for i in range(length):
        pos = rnd_bytes[i] % len(ALPHABET)
        key += ALPHABET[pos]
    return key
    
...

def encrypt(key, msg):
    assert len(key) == len(msg), "For Information-theoretic security the key needs to be as long as the msg."

    ciphertext = ""

    for i in range(len(msg)):
        msg_c = msg[i]
        key_c = key[i]

        if msg_c not in ALPHABET:
            ValueError(f"Can't encrypt char: {msg_c}")

        msg_pos_c = ALPHABET.index(msg_c)
        key_pos_c = ALPHABET.index(key_c)

        new_pos = (msg_pos_c + key_pos_c) % len(ALPHABET)
        ciphertext += ALPHABET[new_pos]

    return ciphertext
```

Notice that the bytes will range from 0 to 255, and given that each byte has an equal probability of being chosen, the original character, and the $$255\mod{63}=3$$ characters that follow, will have a slightly higher probability of ending up in the ciphertext.

We can obtain a maximum of 1000 ciphertexts, but we can simply reconnect any number of times to get more ciphertexts. If we do this enough times, we will naturally observe that at each position of the flag, the highest frequency character that appears in the ciphertext would be one of the 4 characters (original, and the 3 characters that follow) that have a higher probability of appearing in the ciphertext.

```python
inpt = int(input("How many ciphertexts would you like>"))
if 0 < inpt <= 1000:
    for _ in range(inpt):
        key = keygen(len(FLAG))
        print(encrypt(key, FLAG))
else:
    print("Please be reasonable.")
```

At this point, we would know what the flag roughly looks like. Since we are provided with the SHA256 hash of the flag, we can simply brute force the offsets to obtain the original flag.

```python
# Check that flag wasn't corrupted
assert hashlib.sha256(FLAG.encode()).hexdigest() == \
    "59f03b531db63fe65b7b8522badee65488d7a63fd97c3134766faf3d0fde427c", "Flag Corrupt!"
```

There is only a maximum of $$4^{13}$$ combinations to try (the first 4 characters `CSR{` are known, and the highest frequency character is at an offset of either +0, +1, +2 or +3 from the original message).

```python
from pwn import *

import itertools
import string
import hashlib

# cipher = (message from 63-character alphabet + 0 to 255 from os.urandom()) % 63
# Note that it takes 63 characters to "wrap around" back to the original character
# Since each number from 0 to 255 has an equal probability of being chosen,
# the original character, and the 255 % 63 = 3 characters that follow, have a slightly higher chance of being chosen.
ALPHABET = string.ascii_letters + "{}_!$&-%?()"

ciphers = []

for _ in range(20):
    conn = remote("challs.rumble.host" ,17171)
    print(conn.recvuntil(">"))
    conn.sendline("1000")

    for _ in range(1000):
        line = conn.recvline().decode()
        ciphers.append(line.strip())

    conn.recvline()

print(ciphers)

results = ""

for i in range(len(ciphers[0])):
    freq_dict = {alpha: 0 for alpha in ALPHABET}
    for cipher in ciphers:
        freq_dict[cipher[i]] += 1

    most_freq = max(freq_dict, key=freq_dict.get)
    results += most_freq

print(results)

# Starts with CSR{
possibilities_delta = itertools.product((i for i in range(-3, 1)), repeat=len(results) - 4)

i = 0
length = 4 ** (len(results) - 4)

for possibility in possibilities_delta:
    new_result = 'CSR{'

    j = 0
    for char in results[4:]:
        new_result += ALPHABET[(ALPHABET.index(char) + possibility[j]) % len(ALPHABET)]
        j += 1
    
    if hashlib.sha256(new_result.encode()).hexdigest() == "59f03b531db63fe65b7b8522badee65488d7a63fd97c3134766faf3d0fde427c":
        print(new_result)
        break

    i += 1

    if i % 100 == 0:
        print("Progress:", i / length, "Last tried:", new_result)
```

![](<../../.gitbook/assets/image (79).png>)
