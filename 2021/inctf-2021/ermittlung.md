---
description: Basic memory forensics
---

# Ermittlung

## Challenge

**Description**

Our Incident Response team started their investigation on a device found when pinning down a terrorist. They got some doubts while analyzing the device, So they framed these questions can you help them in answering these questions? Our Intelligence report states that the terrorist used a legit chat application for communication among themselves.

**Questions:**

* What is the name of the chat application program?
  * Ex: `Mozilla_Firefox` (Use Name of the program, Not the name of the binary. If there is a space replace it with `_`. )
* When did the user last used this chat application?
  * Answer in `DD-MM-YYYY_HH:MM:SS`. Timestamp in UTC
* How many unread messages are there in the chat application that the user is using?
  * Answer should be an integer `n`.
* What is the current version of the chat application that's being used?
  * Answer in `X.X.XXXX.XXXX`

**Note:**

* Wrap the answers around inctf{}.
* Sample flag: `inctf{Mozilla_Firefox_31-07-2020_19:00:00_10_1.2.2345.5678}`
* Flag is **Case Sensitive**

**MD5 Hash**: `ermittlung.raw 110305F3CF71432B4DFAFD1538CDF850`

**Challenge Author**: [g4rud4](https://twitter.com/\_Nihith)

## Solution

This challenge requires us to do some basic memory forensics using [Volatility](https://www.volatilityfoundation.org).

First of all, let's determine the profile.

```
$ vol.py -f ermittlung.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/Users/zhangzeyu/OneDrive/Documents/CTF/inCTF/ermittlung.raw)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cf60L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2020-07-27 12:27:08 UTC+0000
     Image local date and time : 2020-07-27 17:57:08 +0530
```

Great! We will use the `WinXPSP2x86` profile from now on.

### **What is the name of the chat application program?**

If we look at the process tree, the only relevant process with "chat" functionality is `msimn.exe`, which is Outlook Express.

```
$ vol.py --profile=WinXPSP2x86 pstree -f ermittlung.raw
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x867c6830:System                                      4      0     54    274 1970-01-01 00:00:00 UTC+0000
. 0x8646e020:smss.exe                                 364      4      3     19 2020-07-27 12:25:41 UTC+0000
.. 0x86476458:csrss.exe                               588    364     10    493 2020-07-27 12:25:41 UTC+0000
.. 0x864edda0:winlogon.exe                            612    364     25    543 2020-07-27 12:25:42 UTC+0000
... 0x866a04b8:lsass.exe                              668    612     28    389 2020-07-27 12:25:42 UTC+0000
... 0x8660d280:services.exe                           656    612     16    272 2020-07-27 12:25:42 UTC+0000
.... 0x86281020:svchost.exe                          1292    656     12    180 2020-07-27 12:25:43 UTC+0000
.... 0x86497868:svchost.exe                          1056    656     82   1450 2020-07-27 12:25:42 UTC+0000
..... 0x86213700:wuauclt.exe                         3088   1056      5    109 2020-07-27 12:26:55 UTC+0000
..... 0x865b73c0:wuauclt.exe                          456   1056      9    136 2020-07-27 12:25:56 UTC+0000
..... 0x864b8b10:wscntfy.exe                         1508   1056      1     37 2020-07-27 12:25:58 UTC+0000
.... 0x862672e8:spoolsv.exe                          1716    656     15    122 2020-07-27 12:25:43 UTC+0000
.... 0x864fb560:VBoxService.exe                       828    656      9    126 2020-07-27 12:25:42 UTC+0000
.... 0x86504230:svchost.exe                           964    656      9    263 2020-07-27 12:25:42 UTC+0000
.... 0x862a47a8:svchost.exe                          1116    656      7     88 2020-07-27 12:25:42 UTC+0000
.... 0x865a6558:alg.exe                              1004    656      7    104 2020-07-27 12:25:57 UTC+0000
.... 0x86512c18:svchost.exe                          1908    656      6    107 2020-07-27 12:25:52 UTC+0000
.... 0x86473458:svchost.exe                           888    656     21    220 2020-07-27 12:25:42 UTC+0000
..... 0x86540340:wmiprvse.exe                         448    888      8    191 2020-07-27 12:26:09 UTC+0000
 0x8647dda0:explorer.exe                             1584   1560     20    599 2020-07-27 12:25:43 UTC+0000
. 0x8657ada0:firefox.exe                              144   1584     53    624 2020-07-27 12:26:07 UTC+0000
. 0x8663a788:DumpIt.exe                              3224   1584      1     25 2020-07-27 12:27:05 UTC+0000
. 0x86569790:ctfmon.exe                              1176   1584      1     86 2020-07-27 12:25:57 UTC+0000
. 0x865a27f8:VBoxTray.exe                            1156   1584     13    115 2020-07-27 12:25:57 UTC+0000
. 0x861aec90:msimn.exe                               2132   1584     14    454 2020-07-27 12:26:17 UTC+0000
```

### **When did the user last used this chat application?**

The date and timestamp are provided in the above output (2020-07-27 12:26:17 UTC+0000).

### **How many unread messages are there in the chat application that the user is using?**

A quick Google search on Outlook Express registry keys showed us that the registry key`Software\Microsoft\Windows\CurrentVersion\UnreadMail` contains information about the unread mail. There is a subkey for each email address, and the `MessageCount` value of those subkeys tell us how many unread messages there are.

```
$ vol.py --profile=WinXPSP2x86 printkey -K "Software\Microsoft\Windows\CurrentVersion\UnreadMail\danial.banjamin008@gmail.com" -f ermittlung.raw
Volatility Foundation Volatility Framework 2.6.1
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \Device\HarddiskVolume1\Documents and Settings\crimson\NTUSER.DAT
Key name: danial.banjamin008@gmail.com (S)
Last updated: 2020-07-27 12:26:25 UTC+0000

Subkeys:

Values:
REG_DWORD     MessageCount    : (S) 4
REG_BINARY    TimeStamp       : (S)
0x00000000  42 d8 4e 25 11 64 d6 01                           B.N%.d..
REG_SZ        Application     : (S) msimn
```

There were 4 unread messages.

### **What is the current version of the chat application that’s being used?**

We can use `procdump` to dump the executable.

```
vol.py --profile=WinXPSP2x86 procdump -p 2132 -D msimn -f ermittlung.raw
```

Opening up the file properties in Windows, the answer is staring at us in the face!

![](<../../.gitbook/assets/image (62).png>)

The current version is 6.0.2900.5512.

### Final Flag

`inctf{Outlook_Express_27-07-2020_12:26:17_4_6.0.2900.5512}`
