---
description: LabVIEW
---

# Back to the Lab 2

## Problem

We installed this new HVAC system in the lab using NI instrumentation. Ooh, it's internet-connected. Can you get the flag off of it? It requires "company technician access" but we managed to convince the company to give us some old source code, maybe you can find a workaround?

nc umbcsad.crabdance.com 8000

back\_to\_the\_lab\_2.vi: [https://drive.google.com/file/d/1Bu7xpMiGCEPONd7Hdl6BQL6JXqrFWE6i/view?usp=sharing](https://drive.google.com/file/d/1Bu7xpMiGCEPONd7Hdl6BQL6JXqrFWE6i/view?usp=sharing)

Author: nb

## Solution

Some commands are not shown. We would have to consult the source code.

![](../../.gitbook/assets/e9c002d659d540b98f1532ee9cb12c60.png)

The source code given is a LabVIEW file. Open it using LabVIEW Community. We can view the block diagram for the TCP responder loop.

![](../../.gitbook/assets/04aa6a904a9d42afadbedee68e278d04.png)

We can see that there is a `get_flag` function.

![](../../.gitbook/assets/433ebcf8634e46c98f47489ce9f888ce.png)

We can see that there are 2 conditions from the source code

1. Not yet implemented \(always False\)
2. System time is after 2030

If we look at the list of commands, there is a `set_system_time` and `get_system_time` function.

![](../../.gitbook/assets/774088304f204c159f65d254eeef53f6.png)

If we look at the `set_system_time` function, we see we can set the system time.

![](../../.gitbook/assets/7966a21499964a9ea2b92f9a84d85b02.png)

For instance:

![](../../.gitbook/assets/b7e3affe423b469b9574d7c81b5f4496.png)

However, a check is performed so that we cannot set the system time more than 1 year ahead of the actual time. This check is performed by checking whether the input number is greater than a certain value.

What if we used negative values instead?

![](../../.gitbook/assets/ef5d1c205d914297afae6f16d957fb2f.png)

This sets the time to 2040, and bypasses the `>` check.

Now we can use the `get_flag` command.

![](../../.gitbook/assets/330a3b2d1dbe4b5386be4d3c2ecf3844.png)

