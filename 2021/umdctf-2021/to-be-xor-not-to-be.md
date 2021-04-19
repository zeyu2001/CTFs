# To Be XOR Not To Be

## Problem

You find 2 weird files, maybe [https://en.wikipedia.org/wiki/Exclusive\_or](https://en.wikipedia.org/wiki/Exclusive_or) will help.

## Solution

A simple XOR between the `key` string and the ciphertext. We need to convert `key` to an integer before performing the XOR. After the XOR, we need to convert the result back into a bytestring to get our flag.

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

c = 0b101010101001101010001000100001101010100010001100010110101111011011101110011001100011000000010110101100100011110000100110011011000000111000100000010101100001011000101110101100100011011000100010100100101011100
key = "this is the key!"

print(long_to_bytes(bytes_to_long(key.encode()) ^ c))
```

