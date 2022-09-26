#!/usr/bin/env python3
import time
import sys
import os

# Change to /tmp (which is the only writable directory in the jail)
os.chdir("/tmp")

print("Welcome!")
print("Please input the shellcode to your shared library")
print("This shared library will be assembled and linked against ./main")
print("Try to make ./main print the flag!", flush=True)

time.sleep(1)

def quit():
    print("So what? you can't shellcode?", flush=True)
    print(byte, last_byte, flush=True)
    exit(1)

print("Send the assembly (double newline terminated):", flush=True)

last_byte = b""
binary = b""
while True:
    byte = sys.stdin.buffer.read(1)
    binary += byte
    # allow cancer constraints here
    # man, I really wish there was a way to avoid all this pain!!!
    # lmao
    if b"\x80" <= byte < b"\xff": # 1. printable shellcode
        print(1)
        quit()
    if byte in b"/bi/sh": # 2. no shell spawning shenanigans
        print(2)
        quit()
    if b"\x30" <= byte <= b"\x35": # 3. XOR is banned
        print(3)
        quit()
    if b"\x00" <= byte < b"\x05": # 3. ADD is banned
        print(4)
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
