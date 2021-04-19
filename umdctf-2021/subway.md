# Subway

## Problem

This may seem like a regular substitution cipher, but it doesn't seem to work with a regular alphabet. \(Hint: what non-alphabetic characters does the ciphertext have?\)

## Solution

We can analyse the ciphertext and try to draw conclusions. We know that the flag begins with UMDCTF. By analysing the word lengths, I also knew that the ciphertext started with "The flag is...". For instance, the mappings that I saw are commented below.

We realise that `A -> 0`, `B -> 1`, `C -> 2`, and so on. However, after `O`, things get a bit confusing again. `O -> L`, `P -> M`, and so on. Any results greater than `Z` will start from `0` again.

```python
c = "W74 5o06 8v XP32W5-{qdw_0_vepsog_vx1vwewxwedq_w7ev_wepg}"

# D -> 3
# C -> 2
# T -> W
# H -> 7
# E -> 4
# F -> 5
# I -> 8
# L -> O

m = ''
for char in c:
    if char.isnumeric():
        m += chr(ord('a') + int(char))

    elif char.isalpha():

        if char.lower() < 'o':
            offset = ord(char.lower()) + 26 - ord('o')
        else:
            offset = ord(char.lower()) - ord('o')

        new_char = ord('l') + offset

        if new_char > ord('z'):
            m += str(new_char - ord('z') - 1)
        else:
            m += chr(new_char)

    else:
        m += char

print(m)
```

