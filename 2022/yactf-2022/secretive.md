# Secretive

The app uses AES to encrypt messages, with keys generated from a Linear Congruential Generator (LCG). If we are able to find previously-generated values from the LCG, then we could find the keys used to encrypt the flag.

```python
class Secretizer:
    def __init__(self):
        self._lcg = None

    def init_app(self, app):
        self._lcg = LCG(app.config["LCG_SEED"], app.config["LCG_A"], 
                       app.config["LCG_C"], app.config["LCG_M"])
    
    ...

    def _gen_new_key(self):
        return map(lambda _: self._lcg.random(), range(4))

    def secretize_msg(self, msg):
        key = self._gen_new_key()
        key_str = self._key_to_keystr(key)
        cipher = AESCipher(key_str)
        encrypted_msg = cipher.encrypt(msg)
        return (encrypted_msg, key)
```

The LCG implementation is as follows.

```python
from __future__ import unicode_literals, absolute_import, print_function

class LCG:
	def __init__(self, seed, a, c, m):
		self._seed = seed
		self._x = seed
		self._a = a
		self._c = c
		self._m = m

	def random(self):
		next_x = (self._a * self._x + self._c) % self._m
		self._x = next_x
		return self._x
```

LCGs can be quite easily [broken](https://teamrocketist.github.io/2019/03/31/Crypto-VolgaCtf2019-LG/), allowing us to find the values of `a`, `c` and `m`. We need to submit two messages, so that we get a pair of keys and their corresponding LCG-generated values. This is sufficient for us to find the LCG parameters.

```python
X = []
for _ in range(7):
    X = [344919848, 133572217, 3837144844, 602813605, 3658183952, 3608054065, 2853669428, 2349514525]

Det_X = []
Det_X.append(calc_det(1, 2, X))
Det_X.append(calc_det(2, 3, X))
Det_X.append(calc_det(3, 4, X))
Det_X.append(calc_det(4, 5, X))

found_p = reduce(GCD, Det_X)

mod_inv_a = modInverse((X[2]-X[3]), found_p)
found_a = ((X[3] - X[4])*mod_inv_a) % found_p

found_c = (X[4] - found_a*X[3]) % found_p

print("Found: %d as P, %d as a and %d as c" % (found_p, found_a, found_c))

P, a, c = found_p, found_a, found_c
```

Now, we need to [reverse the LCG](https://stackoverflow.com/questions/2911432/reversible-pseudo-random-sequence-generator) to find previously-generated values.

To do this, note that we can reorder the LCG next-state equation and apply the modular inverse of `a` to find the previous value of `x`.

```
x ≡ a * prevx + c (mod m)
x - c ≡ a * prevx (mod m)
ainverse * (x - c) ≡ ainverse * a * prevx (mod m)
ainverse * (x - c) ≡ prevx (mod m)
```

Starting from the most recently-generated value, we can work backwards to the first 4 generated values, which would be the key used to encrypt the flag.

```python
x = 2349514525
x = (a * x + c) % P

for i in range(1411):
    print('------------------' + str(1411 - i))
    x = (modinv(a, P) * (x - c)) % P
    print(x)
    x = (modinv(a, P) * (x - c)) % P
    print(x)
    x = (modinv(a, P) * (x - c)) % P
    print(x)
    x = (modinv(a, P) * (x - c)) % P
    print(x)
```

With the key found, we can obtain the flag!

![](<../../.gitbook/assets/image (90).png>)
