---
description: Decoding an XOR-encoded file gives us an MS-DOS VHD
---

# SUPER

## Description

HOT

**author**: WhiteHoodHacker

{% hint style="info" %}
The file is encrypted with a repeating XOR cipher
{% endhint %}

## Solution

### The XOR Cipher

The file, when opened, shows the string "SUPERHOT" repeated over and over again in some parts, like the beginning of the file.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 1.03.52 PM.png>)

In other parts, however, there appears to be some scrambled data.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 1.06.42 PM.png>)

This was the major gatekeeper, but as the hint stated, the file is encrypted with a repeating XOR cipher. This explains the repeated "SUPERHOT"s, since $$x\oplus0=x$$. Thus, null bytes (zeros) XOR-ed with "SUPERHOT" would yield "SUPERHOT".

Using "SUPERHOT" as the XOR key, we decode the file.

```python
def repeating_key_xor(text: bytes, key: bytes) -> bytes:

    repetitions = 1 + (len(text) // len(key))
    key = key * repetitions
    key = key[:len(text)]

    return bytes([b ^ k for b, k in zip(text, key)])

with open("SUPERHOT", 'rb') as f:
    text = f.read()

decoded = repeating_key_xor(text, b"SUPERHOT")
print(decoded[:50])

with open("decoded", 'wb') as f:
    f.write(decoded)
```

It turns out the key was indeed "SUPERHOT", as the decoded file was a valid disk image.

![](<../../.gitbook/assets/image (35).png>)

![](<../../.gitbook/assets/image (36).png>)

Indeed, the large portions of zeroes were encoded into repeating "SUPERHOT"s.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 2.34.41 PM.png>)

### A Journey to the Past

Checking the magic bytes at the beginning of the file allows us to fingerprint the file type.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 2.37.44 PM.png>)

From this [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures), we can tell that this is a VHD file.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 2.38.16 PM.png>)

Mounting the VHD with `guestmount -a decoded -i ./mnt -v`, I started exploring the filesystem. The first thing we can try to find out is the OS version. This was easily found to be MS-DOS 6.22 - really old!

```
$ cat mnt/DOS/README.TXT        
README.TXT 

NOTES ON MS-DOS 6.22
====================
This file provides important information not included in the
MICROSOFT MS-DOS USER'S GUIDE or in MS-DOS Help.

...
```

In the filesystem root, there was an interesting `LOG1.IRC` file. It hints at a `superhot.exe` that requires "changing directories many times to reach".

```
$ cat mnt/LOG1.IRC
[13:33] *** Joins: white (whitehoodhacker@sigpwny)
[13:33] <white> Dude, you should play SUPERHOT, it's the most innovative game I've played in years!
[13:33] <white> I'll send it to your file server
[13:35] <someradgamer> epic I'll check it out
[13:38] <someradgamer> why does the setup create so many folders?
[13:38] <someradgamer> I have to change directories so many times to reach superhot.exe
[13:39] <white> Have you tried it yet?
[13:40] <someradgamer> yeah, it's just some dumb title screen, how do I play?
[13:40] <white> That *is* the game
[13:40] <white> you just keep repeating the title
[13:45] <white> oh I almost forgot to mention
[13:46] <white> there's a bug where if you SUPERHOT too much, it will SUPERHOT your entire PC
[13:47] <someradgamer> wait what
[13:48] <someradgamer> that doesn't sound HOT
[13:48] <someradgamer> I'm SUPER deleting this now
[13:48] <someradgamer> what the HOT is happening to my SUPER computer!?
[13:48] <SUPERHOT> SUPERHOT SUPERHOT SUPERHOT
[SU:PE] <RHOT> SUPERHOT SUPERHOT SU
PERHOT SUPERHOT
SUPER
HOT▒ 
```

This referred to an interesting `SUPER` directory in the filesystem root. 

It only contains a directory named `HOT`, which then contains a `SUPER` directory again. This continues until we have `SUPER/HOT/SUPER/HOT/SUPER/HOT/SUPER/HOT/SUPER/HOT`. However, `superhot.exe` was nowhere to be found.

The chat logs did suggest that `someradgamer` might have deleted the file ("I'm SUPER deleting this now") before his computer started malfunctioning.

I looked around a little more, and I guess I "lucked out" when at the corner of my eye, I noticed an `UNDELETE.EXE` executable in the `DOS` directory. 

![](<../../.gitbook/assets/image (37).png>)

I did not know the existence of this command, but I had a feeling that it must have had something to do with it - we're looking for a deleted file, after all. It appears that the [UNDELETE command](https://web.csulb.edu/\~murdock/undelete.html) exists on MS-DOS 5.0 to 6.22, allowing users to recover deleted files if no new files or changes have been made on the disk since the deletion.

Perhaps we can recover the deleted `superhot.exe`? Let's find out! 

Create a new VM on VirtualBox, selecting "DOS" as the OS.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 3.07.14 PM.png>)

When prompted to add a virtual hard disk, select the decoded VHD file.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 3.10.30 PM.png>)

Click on Create, and we have our very own MS-DOS VM! To test our theory, let's navigate to the `C:\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT` folder and run `UNDELETE.EXE`.

This indeed finds a recoverable file, and we are prompted to enter the first character of `?UPERHOT.EXE`. This would obviously be the character `S`.

![](<../../.gitbook/assets/image (38).png>)

### SUPER

The file is successfully "undeleted", and we can run `superhot.exe` to get the flag.

![](<../../.gitbook/assets/image (39).png>)

