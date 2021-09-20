---
description: RSA common modulus attack
---

# RSA Stream

## Description

I made a stream cipher out of RSA! But people say I made a huge mistake. Can you decrypt my cipher?

{% file src="../../.gitbook/assets/rsa\_stream.tar.gz\_0b54cd0e8cff0ee8507e5bc9c7cc503e.gz" caption="Challenge Files" %}

## Solution

The cipher is the result of `stream ^ q`. Since `q` is known, we can reverse the stream:

```python
import gmpy2
from Crypto.Util.number import long_to_bytes, bytes_to_long, getStrongPrime, inverse
from Crypto.Util.Padding import pad

with open("chal.enc", "rb") as f:
    cipher = f.read()

f = open("chal.py","rb").read()

e = 0x10001
for a in range(0,len(f),256):
  q = f[a:a+256]
  if len(q) < 256:q = pad(q, 256)
  q = bytes_to_long(q)
  c = cipher[a:a+256]
  c = bytes_to_long(c)

  stream = c ^ q
  print('e =', e)
  print('stream =', stream)

  e = gmpy2.next_prime(e)
```

The values of `e` are also known. Since the same modulus is used for each value of `e`, we can perform a common modulus attack:

```python
from Crypto.Util.number import long_to_bytes

n = 30004084769852356813752671105440339608383648259855991408799224369989221653141334011858388637782175392790629156827256797420595802457583565986882788667881921499468599322171673433298609987641468458633972069634856384101309327514278697390639738321868622386439249269795058985584353709739777081110979765232599757976759602245965314332404529910828253037394397471102918877473504943490285635862702543408002577628022054766664695619542702081689509713681170425764579507127909155563775027797744930354455708003402706090094588522963730499563711811899945647475596034599946875728770617584380135377604299815872040514361551864698426189453
e1 = 65537
e2 = 65539
c1 = 530489626185248785056851529495092783240974579373830040400135117998066147498584282005309496586285271385506231683106346724399536589882147677475443005358465570312018463021023380158875601171041119440475590494900401582643123591578282709561956760477014082159052783432953072656108109476273394944336635577831111042479694270028769874796026950640461365001794257764912763201380626496424082849888995279082607284985523670452656614243517827527666302856674758359298101361902172718436672098102087255751052784491318925254694362060267194166375635365441545393480159914698549784337629720890519448049478918084785289492116323551062547228
c2 = 1975203020409124908090102805292253341153118000694914516585327724068656268378954127150458523025431644302618409392088176708577321340935694848413811050189138250604932233209407629187417581011490944602128787989061600688049167723157190856755216866030081441779638063158285315586348531096003923657421804826633178796609646683752818371577683682492408250734361651757171442240970926919981163473448896903527190572762083777393917434735180310738365358292823914890490673423902906595054472069189915195457783207514064622885302504323568255100411042585986749851978474243733470017361089849160420069533504193247479827752630064951864510821

def gcdExtended(a, b):  

    # Base Case  
    if a == 0 :   
        return b, 0, 1

    gcd, x1, y1 = gcdExtended(b%a, a)  

    # Update x and y using results of recursive  
    # call  
    x = y1 - (b//a) * x1  
    y = x1  

    return gcd, x, y 

gcd, a, b = gcdExtended(e1, e2)
print(gcd, a, b)

result = (pow(c1, a, n) * pow(c2, b, n)) % n
print(result)

print(long_to_bytes(result))
```

`ACSC{changing_e_is_too_bad_idea_1119332842ed9c60c9917165c57dbd7072b016d5b683b67aba6a648456db189c}`
