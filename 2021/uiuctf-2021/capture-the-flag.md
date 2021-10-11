---
description: LSB steganography
---

# capture the :flag:

## Description

It's always in the place you least expect

Hints:

* LSB
* RGB
* If you have found something previously, try looking again
* Remember to get the full image

**author**: spamakin

## Solution

The EXIF data on the image contains an interesting description.

```
$ exiftool flag.png

ExifTool Version Number         : 12.26
File Name                       : flag.png
Directory                       : .
File Size                       : 2.4 KiB
File Modification Date/Time     : 2021:07:31 22:05:15+08:00
File Access Date/Time           : 2021:07:31 22:06:10+08:00
File Inode Change Date/Time     : 2021:07:31 22:06:09+08:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 120
Image Height                    : 120
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Description                     : LSBs(Pixels[1337:])
Image Size                      : 120x120
Megapixels                      : 0.014
```

It says `LSBs(Pixels[1337:])`. Hmm... maybe it's telling us to get the LSBs of everything after the 1337th pixel.

My initial method was to go row by row, left to right (like reading English).

```python
list(im.getdata())[1337:]
```

This did not yield any meaningful results. 

Plugging it into a steganography tool, like [StegOnline](https://stegonline.georgeom.net/image), helps us to figure out what's going on. In all of the 0th-bit (LSB) planes, there appeared to be some data hidden on the flag pole.

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 12.44.59 PM.png>)

That explains! The pixels were meant to be read column-by-column instead.

Let's rearrange the pixels array to go column-by-column:

```python
from PIL import Image

pix_val = []

with Image.open('flag.png') as secret:
    width, height = secret.size
    for x in range(width):
        for y in range(height):
            pixel = list(secret.getpixel((x, y)))
            pix_val.append(pixel)

pixels = pix_val[1337:]
```

Now, we can read the LSBs of each pixel to get the hidden data.

```python
result = ''
for pixel in pixels:

    for byte in pixel[:3]:
        
        if byte & 1:
            result += '1'
        else:
            result += '0'

        if len(result) == 8:
            
            if result == '0' * 8:
                result = ''
                continue

            char = chr(int(result, 2))
            print(char, end='')

            result = ''
```

We can see the flag right at the beginning. 

![](<../../.gitbook/assets/Screenshot 2021-08-05 at 12.51.25 PM.png>)

