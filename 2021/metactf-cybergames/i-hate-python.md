# I Hate Python

## Description

> I hate Python, and now you will too. Find the password.

```python
import random

def do_thing(a, b):
    return ((a << 1) & b) ^ ((a << 1) | b)

x = input("What's the password? ")
if len(x) != 25:
    print("WRONG!!!!!")
else:
    random.seed(997)
    k = [random.randint(0, 256) for _ in range(len(x))]
    a = { b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k) }
    b = list(range(len(x)))
    random.shuffle(b)
    c = [a[i] for i in b[::-1]]
    print(k)
    print(c)
    kn = [47, 123, 113, 232, 118, 98, 183, 183, 77, 64, 218, 223, 232, 82, 16, 72, 68, 191, 54, 116, 38, 151, 174, 234, 127]
    valid = len(list(filter(lambda s: kn[s[0]] == s[1], enumerate(c))))
    if valid == len(x):
        print("Password is correct! Flag:", x)
    else:
        print("WRONG!!!!!!")

```

## Solution

Okay, let's work this backwards.

```python
kn = [47, 123, 113, 232, 118, 98, 183, 183, 77, 64, 218, 223, 232, 82, 16, 72, 68, 191, 54, 116, 38, 151, 174, 234, 127]
valid = len(list(filter(lambda s: kn[s[0]] == s[1], enumerate(c))))
if valid == len(x):
    print("Password is correct! Flag:", x)
else:
    print("WRONG!!!!!!")
```

We see that `c` is checked against `kn`, and they must be the same in order for our password to be correct.

```python
random.seed(997)
k = [random.randint(0, 256) for _ in range(len(x))]
a = { b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k) }
b = list(range(len(x)))
random.shuffle(b)
c = [a[i] for i in b[::-1]]
```

This part is a little confusing. The first thing to notice is that the RNG is seeded, so the values of `k` and `b` are always the same.

Since we know the value that `c` must be, and the value of `b` after `random.shuffle()` is known, we can recover `a`.

```python
c = kn
print("Need c =", c)
a = [None for _ in range(len(b[::-1]))]
for i in range(len(b[::-1])):
    a[b[::-1][i]] = c[i]
print("Need a =", a)
```

Now, we need to work out what the value of `x` must be. Notice that every character in `x` is passed through the `do_thing()` function, with the corresponding value in `k`.

```python
a = { b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k) }
```

What we need to do is to recover the value of each character in `x`, knowing the corresponding values in `k`. To do that, we need to understand the `do_thing()` function.

```python
def do_thing(a, b):
    return ((a << 1) & b) ^ ((a << 1) | b)
```

We can consider the two cases, where the bit $$b_i$$ is either 0 or 1.

Notice that if $$b_i=0$$, then this simplifies to `0 ^ (a << 1) = (a << 1)`, and if $$b_i=1$$, then this simplifies to `1 ^ (a << 1) = !(a << 1)`.

So this operation flips every bit in `(a << 1)`, where the corresponding bit in `b` is 1. This is the same as `(a << 1) ^ b`.

Hence, to undo this operation and recover the flag, we simply perform the following:

```python
def undo_thing(a, b):
    return (a ^ b) >> 1
```

Here's the full solver script to obtain the password.

```python
def undo_thing(a, b):
    return (a ^ b) >> 1

x = 'a' * 25

random.seed(997)
k = [random.randint(0, 256) for _ in range(len(x))]
print("k =", k)
a = { b: do_thing(ord(c), d) for (b, c), d in zip(enumerate(x), k) }
b = list(range(len(x)))
random.shuffle(b)
c = [a[i] for i in b[::-1]]
kn = [47, 123, 113, 232, 118, 98, 183, 183, 77, 64, 218, 223, 232, 82, 16, 72, 68, 191, 54, 116, 38, 151, 174, 234, 127]
valid = len(list(filter(lambda s: kn[s[0]] == s[1], enumerate(c)))) # i.e. c = kn

print("---")

c = kn
print("Need c =", c)
a = [None for _ in range(len(b[::-1]))]
for i in range(len(b[::-1])):
    a[b[::-1][i]] = c[i]
print("Need a =", a)

undo_a = { b: chr(undo_thing(a[b], d)) for (b, c), d in zip(enumerate(x), k) }
print(''.join(undo_a[i] for i in range(25)))
```

The flag is `MetaCTF{yOu_w!N_th1$_0n3}`.
