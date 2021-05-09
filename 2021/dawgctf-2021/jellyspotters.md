---
description: Python pickle deserialisation
---

# Jellyspotters

## Challenge

The leader of the Jellyspotters has hired you to paint them a poster for their convention, using this painting program. Also, the flag is in ~/flag.txt.

nc umbccd.io 4200

Author: nb

## Solution

B64 encoded pickle string is loaded.

![](../../.gitbook/assets/35f4f9a7c7b3430e898e553101246fdd.png)

Reference: [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)

We can leverage the `__reduce__` method to call `os.system()` with `cat ~/flag.txt`.

![](../../.gitbook/assets/75afcd6be6074897baf166909d6fc4b1.png)

Passing the b64 encoded string into the input, we get the flag.

![](../../.gitbook/assets/0269343d05774da5a46bfa109ec88533.png)

