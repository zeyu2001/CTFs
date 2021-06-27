# Going Active \(Reconnaissance\)

## Messages

```text
└─$ nmap -Pn 52.220.172.156 -sV
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-23 15:02 +08
Nmap scan report for ec2-52-220-172-156.ap-southeast-1.compute.amazonaws.com (52.220.172.156)
Host is up (0.0069s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE    VERSION
21/tcp   open  tcpwrapped
22/tcp   open  tcpwrapped
666/tcp  open  tcpwrapped
8080/tcp open  tcpwrapped

└─$ nc 52.220.172.156 666
CDDC21{F1rst_Fl4G_on_THE_R04D}
```

## Easy Access

```text
└─$ nmap -Pn 13.213.208.230 -sV
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-23 14:57 +08
Nmap scan report for ec2-13-213-208-230.ap-southeast-1.compute.amazonaws.com (13.213.208.230)
Host is up (0.011s latency).
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 21 05:34 pub
|_ftp-bounce: bounce working!
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:116.15.173.9
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open     ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 38:cb:b6:54:5e:98:98:c8:7b:16:80:5f:e0:83:af:69 (RSA)
|   256 39:90:f3:62:d2:14:aa:73:2a:a3:b4:04:bd:ab:21:e1 (ECDSA)
|_  256 3e:7f:18:40:3a:d6:75:6a:b6:2a:54:f1:9c:a2:ef:8d (ED25519)
139/tcp  filtered netbios-ssn
445/tcp  open     netbios-ssn Samba smbd 4.6.2
1047/tcp filtered neod1
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-23T09:34:38
|_  start_date: N/A
```

### FTP

The FTP service allows anonymous logins \(username is `anonymous`\).

```text
ncftp / > ls
pub/
ncftp / > ls pub
note.txt
ncftp / > get pub/note.txt
note.txt:                                              183.00 B   10.55 kB/s
ncftp / >
```

There is a `note.txt` containing user credentials.

```text
└─# cat note.txt  
John, I set a temporary password for you so you can access to your shared folder.
Plz don't put there any sensitive information. TheKeepers might find it somehow!

john:TempTemp123!
```

### SMB

We can then access John's SMB share using the credentials found.

```text
└─$ smbclient --no-pass -L //13.213.208.230

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        john            Disk      Access Restricted
        IPC$            IPC       IPC Service (ip-172-31-32-8 server (Samba, Ubuntu))

└─$ smbclient --user=john \\\\13.213.208.230\\john
smb: \> ls
  .                                   D        0  Mon Jun 21 01:34:48 2021
  ..                                  D        0  Mon Jun 21 01:34:48 2021
  flag.txt                            N       30  Mon Jun 21 02:02:13 2021

                30428560 blocks of size 1024. 27935500 blocks available
smb: \> get flag.txt
getting file \flag.txt of size 30 as flag.txt (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
smb: \>
```

`CDDC21{H0w_d1d_y0u_GET_he4e?}`

## Fuzzing Name

Using a subdirectory enumeration scan, we can find the hidden file in `/assets/flag.txt`.

```text
┌──(root💀kali)-[/home/kali/Documents/CDDC 21]
└─# gobuster dir -u http://fuzzing.globaldominationcorporation.xyz/assets -w /usr/share/dirb/wordlists/common.txt -k -x .txt,.php --threads 10
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://fuzzing.globaldominationcorporation.xyz/assets
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php
[+] Timeout:        10s
===============================================================
2021/06/23 11:41:49 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.txt (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htpasswd.php (Status: 403)
/flag.txt (Status: 200)
===============================================================
2021/06/23 11:42:06 Finished
===============================================================

┌──(root💀kali)-[/home/kali/Documents/CDDC 21]
└─# curl http://fuzzing.globaldominationcorporation.xyz/assets/flag.txt
CDDC21{FuZZ_tH4t_P4th}
```

