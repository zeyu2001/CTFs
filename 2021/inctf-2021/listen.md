---
description: Basic packet sniffing and analysis
---

# Listen

## Challenge

The quieter you become, the more you are able to listen.

**Author:** [f4lc0n](https://twitter.com/theevilsyn)

## Solution

Upon connecting to the VPN, I started sniffing for packets using Wireshark \(the challenge name kind of gave it away!\).

![](../../.gitbook/assets/image%20%2841%29.png)

172.30.0.8 is constantly trying to initiate connections to some seemingly random ports on our machine. Obviously, those ports aren't open, so our machine sends an RST, and no connection is established.

Listening on any of these ports gives us a lot of lorem ipsum text.

![](../../.gitbook/assets/image%20%2843%29.png)

If we look at the statistics, we can see that while the ports are seemingly randomly chosen, two ports \(31336 and 31337\) are receiving way more traffic than the rest.

![](../../.gitbook/assets/image%20%2864%29.png)

I kept listening on port 31337, and eventually, the flag appeared in one of the messages.

![](../../.gitbook/assets/image%20%2842%29.png)

The flag is `inctf{s0_y0u_finally_d3cid3d_t0_listen!!}`

