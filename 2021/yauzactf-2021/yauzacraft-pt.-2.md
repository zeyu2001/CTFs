---
description: Unrestricted file upload leads to PHP webshell
---

# Yauzacraft Pt. 2

## Description

Welcome to the YauzaCraft server! What are you waiting for? Visit our website http://www.minecraft.tasks.yauzactf.com/, register, download the launcher and conquer new heights! Flag path: /flag.txt

P.S. session.minecraft.tasks.yauzactf.com is out of scope!

## Solution

On our user profile, we can find a list of books that we have created on the Minecraft server.

![](<../../.gitbook/assets/Screenshot 2021-08-30 at 11.51.03 AM.png>)

Each book is hosted as a file on `files.minecraft.tasks.yauzactf.com`. For instance, my books were at `/books/VARAVUG66ZZWXG2IFAJ0/FILENAME`, where `FILENAME` is the name of the book in Minecraft.

Going to `/books/VARAVUG66ZZWXG2IFAJ0/` gave the header `X-Powered-By: PHP/7.3.28`, revealing that this was a PHP server.

![](<../../.gitbook/assets/image (65).png>)

Files with "regular" extensions are served as `Content-Type: application/octet-stream` and downloaded. However, using an extension like `.html` will cause the page to be rendered inline.

Knowing that a PHP server is used, we could perhaps upload a `.php` file to run arbitrary PHP code. With a payload like the following, we could obtain a webshell.

![](<../../.gitbook/assets/image (66).png>)

The `.php` extension, however, was filtered recursively. I started testing other similar file extensions and eventually found that the `.phtml` extension (which also allows execution of PHP code) was not filtered and behaved as expected.

![](<../../.gitbook/assets/image (67).png>)

Subsequently, navigating to our uploaded webshell and specifying the `cat /flag.txt` command:

`/books/VARAVUG66ZZWXG2IFAJ0/payload.phtml?cmd=cat%20/flag.txt`

![](<../../.gitbook/assets/Screenshot 2021-08-30 at 12.01.47 PM.png>)

The flag is `YauzaCTF{PHP_minecraft_h4ck3r}`.
