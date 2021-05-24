# Discovery

## Problem

I feel something tickling me, what is it?

## Solution

The description says that something is "tickling" me. It turns out that this was referring to network tickling. When I connected to the VPN, `tcpdump` showed that `10.35.2.134` is periodically pinging me.

![](../../.gitbook/assets/bd5e57f434a24f6a8b169bbc11038da5.png)

Let's open this in Wireshark to inspect the packet contents. The flag is in the ICMP data.

![](../../.gitbook/assets/2b5c82c82ee444f6ade47365d15f9e57.png)

