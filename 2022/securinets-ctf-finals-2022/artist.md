# Artist

> Losing everything is so bad! I lost my keepass password but i guess i wrote it somewhere! Strange thing is there was notepad opened as i remember. But i forgot when exactly!
>
> Securinets{username-pass-openedtimefornotepad}
>
> for the time it should be in this format: YYYY-MM-DD\_HH:MM:SS

First of all, let's find the open time of Notepad. Using Volatility's `pslist`, we find an entry of `notepad.exe` being opened at `2022-05-10 16:42:49` (before KeePass is opened).

```
7336    5688    notepad.exe     0xc18b04f81080  3       -       2       False   2022-05-10 16:42:49.000000      N/A     Disabled
6092    752     svchost.exe     0xc18b02fc2340  3       -       0       False   2022-05-10 16:42:54.000000      N/A     Disabled
4136    5688    KeePass.exe     0xc18b054942c0  9       -       2       False   2022-05-10 16:43:38.000000      N/A     Disabled
```

Now, the description mentions that the KeePass password was written down somewhere. Using `filescan`, we would find the following text file and KeePass database file.

```
0xc18b05e6ebe0	\Users\ctf\Documents\useful.txt	216

...

0xc18b05e71ac0	\Users\ctf\Documents\content.kdbx	216
```

Dumping `useful.txt` reveals the KeePass password, which we can use on the `kdbx` file.

```
the key for it is: qlkdhsqvkyvs1532112837
```

Piecing the information together, we get:

`Securinets{ctf-qlkdhsqvkyvs1532112837-2022-05-10 16:42:49}`
