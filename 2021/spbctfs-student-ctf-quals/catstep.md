# CatStep

## Description

Greeting human!

We want to play a game with you. The mission is simple: you need to guess our flag, that’s all. We use an algorithm to determine the similarity of strings.

## Solution

The server accepts a guess, and calculates the Levenshtein distance between our guess and the flag. 

We can think of the Levinshtien distance as the minimum number of single-character

* Insertions,
* Deletions, or
* Substitutions

required to change our guess to the flag.

We can simply start off with the guess `spbctf{<28 spaces>}`. Since we know the space character will never be part of the flag, the Levenshtien distance simplifies to the number of **wrong** characters in our guess.

This allows us to bruteforce the flag.

```python
import requests
import string
import json

alphabet = string.ascii_letters + string.digits + '_{}'

flag = 'spbctf{'

done = False
i = 0
target_dist = 27
while not done:

    for char in alphabet:

        print(flag + char + ' ' * (27 - i) + '}')
        
        r = requests.post('https://cat-step.disasm.me/',{
            'flag': flag + char  + ' ' * (27 - i) + '}'
        })

        dist = json.loads(r.text)
        print(dist)
        if dist['length'] == target_dist:
            break
    
    flag += char
    print(flag)
    target_dist -= 1

    i += 1
```
