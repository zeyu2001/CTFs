---
description: Collisions in the chaotic hash function.
---

# Chaos

## Problem

What's the fun of rolling up a hash function if it's not chaotic enough?

## Solution

We are given the following source code:

```python
from secret import flag
def ROTL(value, bits, size=32):
    return ((value % (1 << (size - bits))) << bits) | (value >> (size - bits))

def ROTR(value, bits, size=32):
    return ((value % (1 << bits)) << (size - bits)) | (value >> bits)

def pad(pt):
    pt+=b'\x80'
    L = len(pt)
    to_pad = 60-(L%64) if L%64 <= 60 else 124-(L%64)
    padding = bytearray(to_pad) + int.to_bytes(L-1,4,'big')
    return pt+padding

def hash(text:bytes):
    text = pad(text)
    text = [int.from_bytes(text[i:i+4],'big') for i in range(0,len(text),4)]
    M = 0xffff
    x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
    A,B,C,D = 0x401ab257, 0xb7cd34e1, 0x76b3a27c, 0xf13c3adf
    RV1,RV2,RV3,RV4 = 0xe12f23cd, 0xc5ab6789, 0xf1234567, 0x9a8bc7ef
    for i in range(0,len(text),4):
        X,Y,Z,U = text[i]^x,text[i+1]^y,text[i+2]^z,text[i+3]^u
        RV1 ^= (x := (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A)
        RV2 ^= (y := (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B)
        RV3 ^= (z := (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C)
        RV4 ^= (u := (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D)
    for i in range(4):
        RV1 ^= (x := (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A)
        RV2 ^= (y := (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B)
        RV3 ^= (z := (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C)
        RV4 ^= (u := (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D)
    return int.to_bytes( (RV1<<96)|(RV2<<64)|(RV3<<32)|RV4 ,16,'big')

try:
    m1 = bytes.fromhex(input("input first string to hash : "))
    m2 = bytes.fromhex(input("input second string to hash : "))
    print(hash(m1).hex(), hash(m2).hex())
    if m1!=m2 and hash(m1)==hash(m2):
        print(flag)
    else:
        print('Never gonna give you up')
except:
    print('Never gonna let you down')
```

Collisions in this hash function have been proven in the following paper: [https://eprint.iacr.org/2005/403.pdf](https://eprint.iacr.org/2005/403.pdf).  

To solve the challenge, we only need to use two of the examples from the paper.

For instance: 

* fedb02317654a8154576c8f50123ba10bfe54da84832cb1e894c5d830ec3c520
* 0124fdce89ab57eaba89370afedc45ef401ab257b7cd34e176b3a27cf13c3adf

```text
$ nc crypto.zh3r0.cf 2222
input first string to hash : fedb02317654a8154576c8f50123ba10bfe54da84832cb1e894c5d830ec3c520
input second string to hash : 0124fdce89ab57eaba89370afedc45ef401ab257b7cd34e176b3a27cf13c3adf
b'zh3r0{something_chaotic_may_look_random_enough_but_may_be_not_sufficiently_secure} ,courtsey crazy contini : https://littlemaninmyhead.wordpress.com/2015/09/28/so-you-want-to-learn-to-break-ciphers/'
```

### How it Works

For the sake of completeness, however, I will briefly explain one of the collisions: the "appending" case.

For the first input, use two 128-bit blocks. Set the first block to the `x,y,x,u` values:

```python
x,y,z,u = 0x0124fdce, 0x89ab57ea, 0xba89370a, 0xfedc45ef
```

Then, the following

```python
X,Y,Z,U = text[i]^x,text[i+1]^y,text[i+2]^z,text[i+3]^u
```

would be equivalent to

```python
X,Y,Z,U = x^x,y^y,z^z,u^u
```

Since $$a \oplus a=0$$, this sets `X,Y,Z,U` to all 0's.

The following

```python
RV1 ^= (x := (X&0xffff)*(M - (Y>>16)) ^ ROTL(Z,1) ^ ROTR(U,1) ^ A)
RV2 ^= (y := (Y&0xffff)*(M - (Z>>16)) ^ ROTL(U,2) ^ ROTR(X,2) ^ B)
RV3 ^= (z := (Z&0xffff)*(M - (U>>16)) ^ ROTL(X,3) ^ ROTR(Y,3) ^ C)
RV4 ^= (u := (U&0xffff)*(M - (X>>16)) ^ ROTL(Y,4) ^ ROTR(Z,4) ^ D)
```

would therefore be equivalent to

```python
RV1 ^= (x := 0 ^ A)
RV2 ^= (y := 0 ^ B)
RV3 ^= (z := 0 ^ C)
RV4 ^= (u := 0 ^ D)
```

Since $$a \oplus 0=a$$, `x,y,z,u = A,B,C,D` and `RV1 = RV1 ^ A`, `RV2 = RV2 ^ B`, ...

For the second block, simply use the values of `A,B,C,D`. Following the same steps above, we would find that we have again `RV1 = RV1 ^ A`, `RV2 = RV2 ^ B`, ...

Thus, we have

$$
RV_1 = RV_1 \oplus A \oplus A = RV_1 \oplus 0 =RV_1
$$

Without loss of generality, the rotation vectors would therefore go back to their original values.

For the second input, we simply have to append to the first input `A,B,C,D` two more times. Since `x,y,z,u` and `X,Y,Z,U` remain the same, the rotation vectors will again return to their default values.

There are several other collisions mentioned in the paper. 

