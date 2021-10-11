# 1n_jection

## Problem

COVID: \*exists\*\
vaccine jokes: \*challenge_name\*

## Solution

We are given the source code and the output:

```python
from secret import flag

def nk2n(nk):
    l = len(nk)
    if l==1:
        return nk[0]
    elif l==2:
        i,j = nk
        return ((i+j)*(i+j+1))//2 +j
    return nk2n([nk2n(nk[:l-l//2]), nk2n(nk[l-l//2:])])

print(nk2n(flag))
#2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585
```

By studying the code, we can see that this is basically a recursive algorithm that divides the bytestring into two halves at each layer, until the base case where there are either 1 or 2 characters left. We can clearly see that at each layer, the result $$r$$ can be expressed as

$$
r=\frac{(i+j)(i+j+1)}{2}+j
$$

where $$i$$ and $$j$$ are the results of calling the function on the lower and upper half of the input respectively. For each layer, if we are able to recover $$i$$ and $$j$$ from $$r$$, then we would be able to repeat this all the way until the base case, where we would be able to recover the ASCII characters.

Rearranging,

$$
2(r-j)=(i+j)(i+j+1)
$$

Then, we have

$$
i+j=\left \lfloor {\sqrt{2(r-j)}}\right \rfloor
$$

I also noticed one other thing. If we start off with some value of $$i$$ and $$j$$, then increment $$j$$  by $$k$$ while decrementing $$i$$ by the same amount, then we have

$$
r=\frac{((i-k)+(j+k))((i-k)+(j+k)+1)}{2}+(j+k)
$$

$$r$$ is incremented by the same amount, $$k$$.

$$
r=\frac{(i+j)(i+j+1)}{2}+j+k
$$

Using this knowledge, I implemented the following:

```python
def get_i_j(nk):
    j = Decimal(1)
    nk = Decimal(nk)
    sq = 2 * (nk - j)
    i_plus_j = int(sq.sqrt())
    i = i_plus_j - j
    
    test = ((i+j)*(i+j+1)) // 2 + int(j)
    gap = nk - test
    
    if gap < 0:
        i = abs(gap) - 2
        j = i_plus_j - i - 1
        
    else:
        j = gap + 1
        i = i_plus_j - j
        
    assert ((i+j)*(i+j+1))//2 +j == nk
    return i, j
```

Then, since $$i$$ and $$j$$ are essentially the outputs of the "previous" layer, we can create a recursive function that terminates at the base case where we have reduced the output to its original ASCII characters.

```python
def recover_string(nk):
    if nk < 200:
        char = chr(int(nk))
        print(char, end='')
    else:
        i, j = get_i_j(nk)
        recover_string(i)
        recover_string(j)

recover_string(2597749519984520018193538914972744028780767067373210633843441892910830749749277631182596420937027368405416666234869030284255514216592219508067528406889067888675964979055810441575553504341722797908073355991646423732420612775191216409926513346494355434293682149298585)
```

Here's the output. This probably wasn't the intended solution, since the flag talks about a bijection from  $$\mathbb{N^k}$$ to $$\mathbb{N}$$.

![](<../../.gitbook/assets/Screenshot 2021-06-07 at 3.15.32 AM.png>)
