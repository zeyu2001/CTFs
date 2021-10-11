---
description: Recovering the internal state of Python's Mersenne Twister PRNG.
---

# Twist and Shout

## Problem

Wise men once said, "Well, shake it up, baby, now Twist and shout come on and work it on out" I obliged, now the flag is as twisted as my sense of humour\
\
`nc crypto.zh3r0.cf 5555`

## Solution

We are given the following source code:

```python
from secret import flag
from Crypto.Util.number import *
import os
import random

state_len = 624*4
right_pad = random.randint(0,state_len-len(flag))
left_pad = state_len-len(flag)-right_pad
state_bytes = os.urandom(left_pad)+flag+os.urandom(right_pad)

state = tuple( int.from_bytes(state_bytes[i:i+4],'big') for i in range(0,state_len,4) )

random.setstate((3,state+(624,),None))
random.randint(0,0)
outputs = [random.getrandbits(32) for i in range(624)]
print(*outputs,sep='\n')
```

A few things here:

1. The `state` tuple has a fixed length of 624 \* 4, and the flag is hidden inside.
2. Python's `random` pseudo-random number generator (PRNG) state is set to the `state` tuple, with an additional number 624 at the back.
3. Then, 624 32-bit integers are generated using the PRNG and printed.

### Pseudo-RNGs

Note that the left and right padding use `os.urandom()`.

```python
state_bytes = os.urandom(left_pad)+flag+os.urandom(right_pad)
```

This is the cryptographically secure way of generating random numbers in Python. It draws its source of entropy from many real-world unpredictable sources, making it _random_.

The `random` module, on the other hand, implements a deterministic PRNG. Deterministic PRNGs are predictable. For instance, when using the same seed, the "random" numbers will be the same each time.

### Mersenne Twister

In Python, `random` is implemented using the Mersenne Twister. Basically, the RNG works on an internal **state** of 624 32-bit values. The generator also keeps track of the current position `i`  in the state array, and each "random number" is essentially `state[i]` after some mangling.

If we look at the [CPython source code](https://github.com/certik/python-2.7/blob/master/Modules/\_randommodule.c), we can see exactly how this is implemented: 

```c
static unsigned long
genrand_int32(RandomObject *self)
{
    unsigned long y;
    static unsigned long mag01[2]={0x0UL, MATRIX_A};
    /* mag01[x] = x * MATRIX_A  for x=0,1 */
    unsigned long *mt;

    mt = self->state;
    if (self->index >= N) { /* generate N words at one time */
        int kk;

        for (kk=0;kk<N-M;kk++) {
            y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
            mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        for (;kk<N-1;kk++) {
            y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
            mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
        }
        y = (mt[N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK);
        mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

        self->index = 0;
    }

    y = mt[self->index++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return y;
}
```

The `if` statement checks if the index is larger than the size of the array, in which case the state array needs to be regenerated to the "next state".

Otherwise, we can see that it simply does the following to the number at the current index:

```c
y = mt[self->index++];
y ^= (y >> 11);
y ^= (y << 7) & 0x9d2c5680UL;
y ^= (y << 15) & 0xefc60000UL;
y ^= (y >> 18);
return y;
```

### Internal State

Let's take a look at these two lines of the source code:

```python
state = tuple( int.from_bytes(state_bytes[i:i+4],'big') for i in range(0,state_len,4) )
random.setstate((3,state+(624,),None))
```

`random.setstate()` allows us to set a state to control the PRNG. We know that this consists of the state array, but what exactly is the 624 at the back?

The [Python documentation](https://docs.python.org/3/library/random.html#random.setstate) doesn't say much, just that:

> _state_ should have been obtained from a previous call to [`getstate()`](https://docs.python.org/3/library/random.html#random.getstate), and [`setstate()`](https://docs.python.org/3/library/random.html#random.setstate) restores the internal state of the generator to what it was at the time [`getstate()`](https://docs.python.org/3/library/random.html#random.getstate) was called.

and that `getstate()` will

> Return an object capturing the current internal state of the generator. This object can be passed to [`setstate()`](https://docs.python.org/3/library/random.html#random.setstate) to restore the state.

Well, that doesn't really help, but again, the [CPython source code](https://github.com/certik/python-2.7/blob/master/Modules/\_randommodule.c) gives us some answers.

```c
static PyObject *
random_getstate(RandomObject *self)
{
    PyObject *state;
    PyObject *element;
    int i;

    state = PyTuple_New(N+1);
    if (state == NULL)
        return NULL;
    for (i=0; i<N ; i++) {
        element = PyLong_FromUnsignedLong(self->state[i]);
        if (element == NULL)
            goto Fail;
        PyTuple_SET_ITEM(state, i, element);
    }
    element = PyLong_FromLong((long)(self->index));
    if (element == NULL)
        goto Fail;
    PyTuple_SET_ITEM(state, i, element);
    return state;

Fail:
    Py_DECREF(state);
    return NULL;
}
```

Notice how the last element of the state tuple is set? It is set to the value of `self->index`. And we know from the above that the index refers to the current position in the state array.

### Recovering the Internal State

The key idea is that since the state array consists of 624 32-bit integers, we only need 624 32-bit outputs to undo the above mangling and recover the state array.

Credits to More Smoked Leet Chicken for this untempering script! It is taken from [http://mslc.ctf.su/wp/confidence-ctf-2015-rsa2-crypto-500/](http://mslc.ctf.su/wp/confidence-ctf-2015-rsa2-crypto-500/).

```python
#-*- coding:utf-8 -*-

TemperingMaskB = 0x9d2c5680
TemperingMaskC = 0xefc60000

def untemper(y):
    y = undoTemperShiftL(y)
    y = undoTemperShiftT(y)
    y = undoTemperShiftS(y)
    y = undoTemperShiftU(y)
    return y

def undoTemperShiftL(y):
    last14 = y >> 18
    final = y ^ last14
    return final

def undoTemperShiftT(y):
    first17 = y << 15
    final = y ^ (first17 & TemperingMaskC)
    return final

def undoTemperShiftS(y):
    a = y << 7
    b = y ^ (a & TemperingMaskB)
    c = b << 7
    d = y ^ (c & TemperingMaskB)
    e = d << 7
    f = y ^ (e & TemperingMaskB)
    g = f << 7
    h = y ^ (g & TemperingMaskB)
    i = h << 7
    final = y ^ (i & TemperingMaskB)
    return final

def undoTemperShiftU(y):
    a = y >> 11
    b = y ^ a
    c = b >> 11
    final = y ^ c
    return final
```

After receiving the 624 outputs from the server, we can store them in an `outputs` array and recover the original state:

```python
from mt import untemper

mt_state = tuple(list(map(untemper, outputs)) + [0])
random.setstate((3, mt_state, None))
outputs2 = [random.getrandbits(32) for i in range(624)]

# Sanity check
for i in range(len(outputs2)):
    assert outputs2[i] == outputs[i]
```

If the sanity check passes, we have successfully recovered the original state of the MT PRNG. However, our work is not done! Remember how the number 624 was added to the back of the state tuple?

```python
random.setstate((3,state+(624,),None))
```

Well, looking back at the CPython source above, we know that this means that before the first random output is even generated, the state array was reconstructed.

```python
if (self->index >= N) { /* generate N words at one time */
    int kk;

    for (kk=0;kk<N-M;kk++) {
        y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
        mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1UL];
    }
    for (;kk<N-1;kk++) {
        y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
        mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
    }
    y = (mt[N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK);
    mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];

    self->index = 0;
}
```

The state we obtained from our script above is from unmangling the previous 624 outputs, therefore giving us a state array that starts from **index 0**. This is exactly the state array that would be generated after the MT generator notices that the current position in the array is 624.

### Recovering the Previous State

What we need to do, then, is to recover the previous state of the generator. I found this great [post](https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part\_4.html) containing an algorithm to recover the previous state array.

The algorithm looks like this:

```c
for (int i = 623; i >= 0; i--) {
  int result = 0;
  // first we calculate the first bit
  int tmp = state[i];
  tmp ^= state[(i + 397) % 624];
  // if the first bit is odd, unapply magic
  if ((tmp & 0x80000000) == 0x80000000) {
    tmp ^= 0x9908b0df;
  }
  // the second bit of tmp is the first bit of the result
  result = (tmp << 1) & 0x80000000;

  // work out the remaining 31 bits
  tmp = state[(i - 1 + 624) % 624];
  tmp ^= state[(i + 396) % 624];
  if ((tmp & 0x80000000) == 0x80000000) {
    tmp ^= 0x9908b0df;
    // since it was odd, the last bit must have been 1
    result |= 1;
  }
  // extract the final 30 bits
  result |= (tmp << 1) & 0x7fffffff;
  state[i] = result;
```

We can then recover the previous state:

```python
state = tuple( int.from_bytes(state_bytes[i:i+4],'big') for i in range(0,state_len,4) )
random.setstate((3,state+(624,),None))  # This state has index 624

...

# From the state with index 0, recover previous state with index 624.
def get_prev_state(state):
    for i in range(623, -1, -1):
        result = 0
        tmp = state[i]
        tmp ^= state[(i + 397) % 624]
        if ((tmp & 0x80000000) == 0x80000000):
            tmp ^= 0x9908b0df
        result = (tmp << 1) & 0x80000000
        
        tmp = state[(i - 1 + 624) % 624]
        tmp ^= state[(i + 396) % 624]
        if ((tmp & 0x80000000) == 0x80000000):
            tmp ^= 0x9908b0df
            result |= 1
        
        result |= (tmp << 1) & 0x7fffffff
        state[i] = result
    
    return state
    
prev_state = get_prev_state(list(mt_state[:624]))

# Sanity check
for i in range(1, len(state)):
    assert state[i] == prev_state[i]
```

Sidenote: recovering the previous state essentially allows us to obtain "past" outputs. Being able to know both past and future outputs can be a serious security flaw in real-world applications. In a real application, we might obtain the required 624 outputs to recover the internal state of the PRNG via consecutive web requests, etc.

### Solving the Challenge

Once we obtain the original state, we simply have to convert the numbers in the tuple to their corresponding bytes and look for the flag in the output.

```python
from Crypto.Util.number import *
result = b""
for num in prev_state:
    result += long_to_bytes(num)
    
print(result)
```

Here's the complete solver script:

```python
from pwn import *
from Crypto.Util.number import *
from mt import untemper

conn = remote('crypto.zh3r0.cf', 5555)

outputs = []
for i in range(624):
    num = int(conn.recvline().decode().strip())
    outputs.append(num)
    
mt_state = tuple(list(map(untemper, outputs)) + [0])

def get_prev_state(state):
    for i in range(623, -1, -1):
        result = 0
        tmp = state[i]
        tmp ^= state[(i + 397) % 624]
        if ((tmp & 0x80000000) == 0x80000000):
            tmp ^= 0x9908b0df
        result = (tmp << 1) & 0x80000000
        
        tmp = state[(i - 1 + 624) % 624]
        tmp ^= state[(i + 396) % 624]
        if ((tmp & 0x80000000) == 0x80000000):
            tmp ^= 0x9908b0df
            result |= 1
        
        result |= (tmp << 1) & 0x7fffffff
        state[i] = result
    
    return state
    
prev_state = get_prev_state(list(mt_state[:624]))

result = b""
for num in prev_state:
    result += long_to_bytes(num)
    
print(result)
```

And the output contains the flag:

![](<../../.gitbook/assets/image (11).png>)
