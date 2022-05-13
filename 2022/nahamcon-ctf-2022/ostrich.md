# Ostrich

NahamCon has non-guessy steganography challenges! Props to the organizers.

We are given the following source code that was used to generate the resulting image. Both the original and final images are given.

```python
import imageio
from PIL import Image, GifImagePlugin
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
import random
from apng import APNG

filenames = []
flag = "REDACTED" 

orig_filename = "ostrich.jpg"
orig_image = Image.open(orig_filename)
pixels = orig_image.load()
width, height = orig_image.size
images = []

for i in range(len(flag)):
    new_filename = f'./images/ostrich{i}.png'
    new_image = Image.new(orig_image.mode, orig_image.size)
    new_pixels = new_image.load()
    for x in range(width):
        for y in range(height):
            new_pixels[x,y] = orig_image.getpixel((x, y))

    x = random.randrange(0,width)
    y = random.randrange(0,height)
    pixel = list(orig_image.getpixel((x, y)))
    while(pixel[2] == 0):
        x = random.randrange(0,width)
        y = random.randrange(0,height)
        pixel = list(orig_image.getpixel((random.randrange(0,width), random.randrange(0,height))))
    
    new_val = l2b(pixel[2]*ord(flag[i]))
    pixel[0] = new_val[0]
    if len(new_val) > 1:
        pixel[1] = new_val[1]
    pixel[2] = 0

    new_pixels[x, y] = (pixel[0], pixel[1], pixel[2])
    new_image.save(new_filename)
    filenames.append(new_filename)
    images.append(new_image)

APNG.from_files(filenames, delay=0).save("result.apng")

```

First of all, the result is an `.apng` file, which is a series of PNGs that form an animated image (similar to a GIF). We can get the individual frames by doing:

```python
im = APNG.open("result.apng")
for i, (png, control) in enumerate(im.frames):
    png.save("frames/{i}.png".format(i=i))
```

If we look into the provided source code, we see that each character of the flag is encoded by taking the "blue" value in the RGB of a random pixel, multiplying that by the ASCII code of the flag character, and placing the result into the "red" and "green" parts of the RGB value.

Therefore, for each resulting image, we simply have to identify the pixel that is different, and do:

$$
c=\frac{\text{red} * 256 + \text{green}}{blue}
$$

```python
from apng import APNG
from PIL import Image

origImage = Image.open("ostrich.jpg")
res = ''

for i in range(38):
    newImg = Image.open(f"frames/{i}.png")
    
    found = False
    for x in range(newImg.size[0]):
        for y in range(newImg.size[1]):
            pixel = newImg.getpixel((x, y))
            origPixel = origImage.getpixel((x, y))
            if pixel != origPixel:
                print("[+] {} => {}".format(origPixel, pixel))
                if pixel[1]:
                    val = pixel[0] * 256 + pixel[1]
                else:
                    val = pixel[0]

                factor = val / origPixel[2]
                res += chr(int(factor))
                print(res)

                found = True
                break

        if found:
            break
```
