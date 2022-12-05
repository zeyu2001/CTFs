---
description: Simple beginner challenge about base-n encodings
---

# back\_to\_basics

## Description

Shoutout to those people who think that base64 is proper encryption

**author**: epistemologist

{% file src="../../.gitbook/assets/main.py" %}
main.py
{% endfile %}

{% file src="../../.gitbook/assets/flag_enc" %}
flag\_enc
{% endfile %}

## Solution

We are provided with the following source code.

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from gmpy2 import mpz, to_binary
#from secret import flag, key

ALPHABET = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ#")

def base_n_encode(bytes_in, base):
	  return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()

def base_n_decode(bytes_in, base):
	  bytes_out = to_binary(mpz(bytes_in, base=base))[:1:-1]
	  return bytes_out

def encrypt(bytes_in, key):
	  out = bytes_in
	  for i in key:
		    print(i)
		    out = base_n_encode(out, ALPHABET.index(i))
	  return out

def decrypt(bytes_in, key):
	  out = bytes_in
	  for i in key:
		    out = base_n_decode(out, ALPHABET.index(i))
	  return out

"""
flag_enc = encrypt(flag, key)
f = open("flag_enc", "wb")
f.write(flag_enc)
f.close()
"""
```

This is a custom encryption algorithm that repeatedly base-_n_ encodes the ciphertext for each character of the key. In the encryption function, we see that the base is determined by the position of the key character `i` in the `ALPHABET`.

```python
def encrypt(bytes_in, key):
	  out = bytes_in
	  for i in key:
		    print(i)
		    out = base_n_encode(out, ALPHABET.index(i))
	  return out
```

The `base_n_encode()` simply implements the base-_n_ encoding.

```python
def base_n_encode(bytes_in, base):
	  return mpz(bytes_to_long(bytes_in)).digits(base).upper().encode()
```

The flaw in this encryption scheme is that we know every input to `base_n_encode()`, other than the original plaintext, must also be a base-_n_ encoded string. This allows us to bruteforce the key by ruling out invalid decoded outputs.

The following solver script implements this. Since there might be multiple valid bases, a depth-first search is performed on all possible bases. This turned out to be unnecessary, because the smallest valid base worked every time.

```python
def decrypt_flag(enc, base):

    if base:

        try:
            enc = base_n_decode(enc, base).decode()

        except:
            return False
            
        else:
            if "uiuctf" in enc:
                return enc

    for possible_base in range(2, len(ALPHABET)):

        decrypted = decrypt_flag(enc, possible_base)

        # This base works
        if decrypted:
            return decrypted
    
    return False

with open('flag_enc', 'rb') as f:
    enc = f.read()
    
print(decrypt_flag(enc, None))
```

Running this gives us the flag, `uiuctf{r4DixAL}`.

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 5.05.58 PM.png>)
