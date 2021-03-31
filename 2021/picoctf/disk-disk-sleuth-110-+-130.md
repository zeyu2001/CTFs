---
description: Disk image analysis
---

# Disk, Disk, Sleuth! \(110 + 130\)

### DDS 1

`srch_strings dds1-alpine.flag.img | grep picoCTF`

![](../../.gitbook/assets/8d92d92e244a478eb9860bef29412bc6.png)

### DDS 2

Note that our Linux partition offset is 2048. We will need to specify this in the `-o 2048` option subsequently.

![](../../.gitbook/assets/3f2d64f62fb6454eb5906fec56ccf62a.png)

Find the location of the file:

![](../../.gitbook/assets/f359b28b11a74547bb13b1665ec83bba.png)

Recover the files:

`tsk_recover -e -o 2048 dds2-alpine.flag.img extracted`

![](../../.gitbook/assets/346fe11a22db4eba82235a2c0fe836b3.png)

Then navigate to the location \(`root/down-at-the-bottom.txt`\) found previously. Our flag is there.

![](../../.gitbook/assets/de8ba81541734fc5b7f59b78c855665f.png)

