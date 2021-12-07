# Ransomware Patch

## Description

> You've captured a communication containing a patch for the source code of a well-known ransomware program. It contains an update for a library the program uses, as well as an interesting file named `key`. Can you crack [this ZIP](https://metaproblems.com/f807f1b6beeecc351ab76d1353e403e8/ransomware-final.zip) and figure out the contents of `key`?
>
> _\*made with 7ZIP deflate on "Normal" settings_

{% file src="../../.gitbook/assets/ransomware-final.zip" %}

## Solution

We could use `7z l -slt ransomware-final.zip` to list detailed information about the ZIP file.

The first observation to be made is that we can find the files listed in the archive online.

```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-11-30 06:40:19 D....            0            0  AES
2021-11-30 05:35:38 ....A        19017         5536  AES/aes.c
2021-11-30 05:35:38 ....A         2790          966  AES/aes.h
2021-11-30 05:35:38 ....A          184          136  AES/aes.hpp
2021-11-30 05:35:38 ....A          366          202  AES/CMakeLists.txt
2021-11-30 05:35:38 ....A         2050          774  AES/conanfile.py
2021-11-30 05:35:38 ....A          279          205  AES/library.json
2021-11-30 05:35:38 ....A          557          366  AES/library.properties
2021-12-04 01:29:36 ....A         1261          602  AES/Makefile
2021-11-30 05:35:38 ....A         4783         2064  AES/README.md
2021-11-30 05:35:38 ....A        15539         2702  AES/test.c
2021-11-30 05:35:38 ....A           37           49  AES/test.cpp
2021-11-30 05:43:46 D....            0            0  AES/test_package
2021-11-30 05:35:38 ....A          313          221  AES/test_package/CMakeLists.txt
2021-11-30 05:35:38 ....A          413          237  AES/test_package/conanfile.py
2021-11-30 05:35:38 ....A         1211          698  AES/unlicense.txt
2021-11-30 05:38:16 ....A           33           45  key
------------------- ----- ------------ ------------  ------------------------
2021-12-04 01:29:36              48833        14803  15 files, 2 folders
```

By Googling some of the file names, we find that the files under the `AES` directory are from this GitHub repository.

{% embed url="https://github.com/kokke/tiny-AES-c" %}

In the detailed information, we find that the file we want to decrypt, `key`, was encrypted using the `ZipCrypto Store` algorithm. This is a legacy method that is vulnerable to a [known plaintext attack](https://anter.dev/posts/plaintext-attack-zipcrypto/).&#x20;

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 5.17.55 PM.png>)

This attack can be performed using the `bkcrack` tool below.

{% embed url="https://github.com/kimci86/bkcrack" %}

One complication, though, is that all of the other files in the archive are encrypted using `ZipCrypto Deflate`, which makes the cracking much harder - well, all but one! The `test.cpp` file was similarly encrypted using the vulnerable `ZipCrypto Store`.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 5.21.20 PM.png>)

We could thus use the plaintext of this file, which we can find from the GitHub repository, to crack the keys: `./bkcrack -C ransomware-final.zip -c "AES/test.cpp" -p test.cpp`

This gives us the keys: `a71f05f4 18438c7b 1cf62c29`

Using these, we can crack the `key` file: `./bkcrack -C ransomware-final.zip -c key -k a71f05f4 18438c7b 1cf62c29 -d key.out`

The key is `MetaCTF{license_is_hard_to_spell}`.
