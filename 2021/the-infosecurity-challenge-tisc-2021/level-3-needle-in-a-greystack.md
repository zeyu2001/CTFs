# Level 3 - Needle in a Greystack

> An attack was detected on an internal network that blocked off all types of executable files. How did this happen?\
> \
> Upon further investigations, we recovered these 2 grey-scale images. What could they be?

**Disclaimer:** I did not manage to fully solve this during the competition itself. I did shortly after (an hour after the CTF), though, with the help of my friend Rainbowpigeon :smile:

### Understanding the BMP Files

I noticed early on that `1.bmp` was essentially a Windows executable, but split into chunks with the order reversed. This is pretty obvious given the `MZ` and `PE` file signatures at the end. This allowed me to successfully recover the executable, but as we will see later, was insufficient for me to solve the challenge.

I did not notice that these 'chunks' were essentially the different bitmap lines, which 010 Editor would generously show me!

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 6.54.26 PM.png>)

These lines consist of data followed by some padding (null bytes).

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.04.19 PM.png>)

Extracting the data (in reverse order) and removing the padding bytes thus gives us the executable.

```python
chunk_size = 148

with open('decoded' ,'rb') as infile, open('out.txt', 'wb') as outfile:
	data = infile.read()
	i = len(data) - chunk_size
	
	while i > 0:
		outfile.write(data[i:i + chunk_size][:-3])
		i -= chunk_size
		
	outfile.write(data[:chunk_size])
```

### Understanding the Executable

First of all, we need a `.txt` file as an argument.

![Checking the File Extension](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.11.26 PM.png>)

Failing which, the file will not be read!

![Reading the File](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.14.16 PM.png>)

Upon reading the file, its contents will then go thorugh a decoding algorithm (we don't actually need to know how it works for the purpose of this challenge).

![Decoding the File Contents](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.18.00 PM.png>)

Once decoded, a second function is called. The decoded buffer must then start with 0x5A4D (i.e. `MZ`), otherwise the function exits.

![Checking the Magic Bytes](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.22.27 PM.png>)

Subsequently, a DLL is loaded. Given that the decoded buffer must start with `MZ`, it is clear that we have to make our input file successfully decode into a DLL in memory, which is then executed.

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.25.08 PM.png>)

I figured this much out during the competition, but the missing piece was finding an appropriate input file that will decode successfully. Supplying the contents of `2.bmp` yielded the `MZ` file signature _somewhere_ in the decoded contents, but not at the start as was expected.

It turns out that `2.bmp` followed the same structure as `1.bmp`, and with the newfound knowledge about the bitmap file structure, I only had to tweak the previous script to accomodate the line and padding sizes of this second bitmap file.

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.30.56 PM.png>)

```python
chunk_size = 100

with open('2.bmp' ,'rb') as infile, open('out.txt', 'wb') as outfile:
	data = infile.read()
	i = len(data) - chunk_size
	
	while i > 0:
		outfile.write(data[i:i + chunk_size][:-1])
		i -= chunk_size
		
	outfile.write(data[:chunk_size])
```

Great, we have some progress!

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.33.35 PM.png>)

We want to know what the DLL is doing, so let's set a breakpoint and dump the decoded DLL from memory.

![Decoded DLL in Memory](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.40.06 PM.png>)

A `key.txt` file is required.

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 7.57.27 PM.png>)

Now, the un-decoded version of `2.bmp` looks conspicuously like a wordlist... and it turns out that while I was staring at the "wrong" stuff and trying to figure out its purpose, I had already stumbled upon what looks like a key!

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 8.01.15 PM.png>)

With the correct key file, we get the flag.

![](<../../.gitbook/assets/Screenshot 2021-11-19 at 8.02.43 PM.png>)
