# ARC6969 Pt. 1

## Description

The ARC6969 is an old and forgotten architecture used in a military computers during Cold War. Although we don't have the computers anymore, we got CPU manual and a few programs.

{% file src="../.gitbook/assets/manual\_1.pdf" caption="manual\_1.pdf" %}

{% file src="../.gitbook/assets/rom\_1.bin" caption="rom\_1.bin" %}

## Solution

The idea behind this challenge is the same as that of the previous [RISC 8bit CPU](risc-8bit-cpu.md) challenge. The extra difficulty stems from the increased number of instructions, I/O handling, and a more complex flag register.

### Comparison

There are now 4 flags that can be set by the comparison instructions.

![](../.gitbook/assets/image%20%2868%29.png)

The first three are pretty straightforward. Note that for signed numbers, the MSB determines the sign \(1 for negative, 0 for positive\).

The overflow flag can be a bit tricky - one trick is to check the sign of the compared operands and the result. If both $$R_x$$ and $$R_y$$ have the same sign, but $$R_x-R_y$$ yields a different sign, then an overflow has occurred.

```python
if opcode == 4 or opcode == 5:
    Rx = int(curr_instruction[8:13], 2)
    Ry_Imm8 = int(curr_instruction[16:], 2)

    # print(f"COMPARISON; opcode: {opcode}; Rx: {Rx}; Ry/Imm8: {Ry_Imm8}")

    fr &= 0b0000

    if opcode == 4:
        if registers[Rx] == registers[Ry_Imm8]:
            fr |= 0b0001
        
        if registers[Ry_Imm8] > registers[Rx]:
            fr |= 0b0010

        if (registers[Rx] - registers[Ry_Imm8]) & 0b10000000:
            fr |= 0b0100

        # Rx and Ry have the same sign, but Rx - Ry has a different sign
        if registers[Rx] & 0b10000000 == registers[Ry_Imm8] & 0b10000000 and \
            (registers[Rx] - registers[Ry_Imm8]) & 0b10000000 != registers[Rx] & 0b10000000:
            fr |= 0b1000

    else:

        if registers[Rx] == Ry_Imm8:
            fr |= 0b0001
        
        if Ry_Imm8 > registers[Rx]:
            fr |= 0b0010

        if (registers[Rx] - Ry_Imm8) & 0b10000000:
            fr |= 0b0100

        # Rx and Ry have the same sign, but Rx - Ry has a different sign
        if registers[Rx] & 0b10000000 == Ry_Imm8 & 0b10000000 and \
            (registers[Rx] - Ry_Imm8) & 0b10000000 != registers[Rx] & 0b10000000:
            fr |= 0b1000
```

### I/O Devices

There are two I/O interfaces - a GPU and a serial interface.

![](../.gitbook/assets/image%20%2865%29.png)

It is given that the GPU display is 64 x 32. This is represented by a 2D array, where each element represents a pixel. The GPU is not yet needed for this challenge, so we'll touch up the `display_screen()` function in the next challenge. The serial I/O is pretty standard - we'll accept user input one byte at a time.

```python
gpu = [[0 for _ in range(64)] for _ in range(32)]
gpu_x = 0
gpu_y = 0

...

# IO Device Communication
elif opcode == 21:
    Rx = int(curr_instruction[8:13], 2)
    Imm3 = int(curr_instruction[13:], 2)

    # print(f"IO; Rx: {Rx}; Imm3: {Imm3}")

    if Imm3 == 1:
        gpu_x = registers[Rx]

    elif Imm3 == 2:
        gpu_y = registers[Rx]

    elif Imm3 == 3:
        gpu[gpu_y][gpu_x] = registers[Rx]
    
    elif Imm3 == 4:
        # Draw buffer
        display_screen(gpu)
    
    elif Imm3 == 5:
        # Return the number of bytes currently in serial buffer
        registers[Rx] = int(input("Number of bytes: "))

    elif Imm3 == 6:
        # Read 1 byte from serial buffer
        registers[Rx] = int(input("Byte: "))

    elif Imm3 == 7:
        # Write 1 byte to serial out
        print(chr(registers[Rx]), end='')
```

One last detail - since there are subtraction instructions, we have to handle the cases where the result becomes negative. Taking the lower 8 bits is the same as subtracting the result from 256.

```python
# 8 bit
for i in range(len(registers)):

    while registers[i] >= 256:
        registers[i] -= 256

    while registers[i] < 0:
        registers[i] = 256 - abs(registers[i])
```

Putting everything together, the full emulator script is as follows:

```python
#!/usr/bin/python3

ROM = "58 84 00 ... 45 F7 A0"

registers = [0 for _ in range(32)]

pc = 0     # Program Counter
fr = 0     # Flag Register

rom = [int(x, 16) for x in ROM.split()]
memory = rom + [0 for _ in range(0xffff + 1 - len(rom))]

gpu = [[0 for _ in range(64)] for _ in range(32)]
gpu_x = 0
gpu_y = 0

def display_screen(gpu):
    print(gpu)

done = False
while not done:
    
    curr_instruction = bin(memory[pc])[2:].zfill(8)
    opcode = int(curr_instruction[:5], 2)
    
    # 24 bits per instruction
    if opcode != 21:
        curr_instruction = memory[pc:pc+3]
        pc += 3
    
    # 16 bits per instruction
    else:
        curr_instruction = memory[pc:pc+2]
        pc += 2

    curr_instruction = ''.join([bin(x)[2:].zfill(8) for x in curr_instruction])

    # Comparison
    if opcode == 4 or opcode == 5:
        Rx = int(curr_instruction[8:13], 2)
        Ry_Imm8 = int(curr_instruction[16:], 2)

        # print(f"COMPARISON; opcode: {opcode}; Rx: {Rx}; Ry/Imm8: {Ry_Imm8}")

        fr &= 0b0000

        if opcode == 4:
            if registers[Rx] == registers[Ry_Imm8]:
                fr |= 0b0001
            
            if registers[Ry_Imm8] > registers[Rx]:
                fr |= 0b0010

            if (registers[Rx] - registers[Ry_Imm8]) & 0b10000000:
                fr |= 0b0100

            # Rx and Ry have the same sign, but Rx - Ry has a different sign
            if registers[Rx] & 0b10000000 == registers[Ry_Imm8] & 0b10000000 and \
                (registers[Rx] - registers[Ry_Imm8]) & 0b10000000 != registers[Rx] & 0b10000000:
                fr |= 0b1000

        else:

            if registers[Rx] == Ry_Imm8:
                fr |= 0b0001
            
            if Ry_Imm8 > registers[Rx]:
                fr |= 0b0010

            if (registers[Rx] - Ry_Imm8) & 0b10000000:
                fr |= 0b0100

            # Rx and Ry have the same sign, but Rx - Ry has a different sign
            if registers[Rx] & 0b10000000 == Ry_Imm8 & 0b10000000 and \
                (registers[Rx] - Ry_Imm8) & 0b10000000 != registers[Rx] & 0b10000000:
                fr |= 0b1000

    # Arithmetic
    elif opcode <= 13:
        Rx = int(curr_instruction[6:11], 2)
        Ry = int(curr_instruction[11:16], 2)
        Rz_Imm8 = int(curr_instruction[16:], 2)

        # print(f"ARITHMETIC; opcode: {opcode}; Rx: {Rx}; Ry: {Ry}; Rz/Imm8: {Rz_Imm8}")

        if opcode == 0:
            registers[Rx] = registers[Ry] + registers[Rz_Imm8]

        elif opcode == 1:
            registers[Rx] = registers[Ry] + Rz_Imm8
        
        elif opcode == 2:
            registers[Rx] = registers[Ry] - registers[Rz_Imm8]

        elif opcode == 3:
            registers[Rx] = registers[Ry] - Rz_Imm8

        elif opcode == 6:
            registers[Rx] = registers[Ry] | registers[Rz_Imm8]

        elif opcode == 7:
            registers[Rx] = registers[Ry] | Rz_Imm8

        elif opcode == 8:
            registers[Rx] = registers[Ry] ^ registers[Rz_Imm8]

        elif opcode == 9:
            registers[Rx] = registers[Ry] ^ Rz_Imm8
        
        elif opcode == 10:
            registers[Rx] = registers[Ry] & registers[Rz_Imm8]
        
        elif opcode == 11:
            registers[Rx] = registers[Ry] & Rz_Imm8
        
        elif opcode == 12:
            registers[Rx] = registers[Ry] << registers[Rz_Imm8]

        elif opcode == 13:
            registers[Rx] = registers[Ry] >> registers[Rz_Imm8]

    # Memory Operations
    elif opcode == 14 or opcode == 15:

        Rx = int(curr_instruction[6:11], 2)
        Ry = int(curr_instruction[11:16], 2)
        Rz = int(curr_instruction[19:], 2)

        # print(f"MEMORY OPERATION; opcode: {opcode}; Rx: {Rx}; Ry: {Ry}; Rz: {Rz}")

        addr = 256 * registers[Ry] + registers[Rz]

        if opcode == 14:
            registers[Rx] = memory[addr]
        
        elif opcode == 15:
            memory[addr] = registers[Rx]

    # IO Device Communication
    elif opcode == 21:
        Rx = int(curr_instruction[8:13], 2)
        Imm3 = int(curr_instruction[13:], 2)

        # print(f"IO; Rx: {Rx}; Imm3: {Imm3}")

        if Imm3 == 1:
            gpu_x = registers[Rx]

        elif Imm3 == 2:
            gpu_y = registers[Rx]

        elif Imm3 == 3:
            gpu[gpu_y][gpu_x] = registers[Rx]
        
        elif Imm3 == 4:
            # Draw buffer
            display_screen(gpu)
        
        elif Imm3 == 5:
            # Return the number of bytes currently in serial buffer
            registers[Rx] = int(input("Number of bytes: "))

        elif Imm3 == 6:
            # Read 1 byte from serial buffer
            registers[Rx] = int(input("Byte: "))

        elif Imm3 == 7:
            # Write 1 byte to serial out
            print(chr(registers[Rx]), end='')

    elif opcode == 23:
        # print("HLT")
        done = True

    else:
        Imm16 = int(curr_instruction[8:], 2)

        # print(f"JUMP; opcode: {opcode}; Imm16: {Imm16}")

        if opcode == 24:
            registers[31] = pc
            pc = Imm16
        
        elif opcode == 25:
            pc = registers[31]

        elif opcode == 16:
            pc = Imm16
        
        elif opcode == 17:
            if fr & 0b0001:
                pc = Imm16
            
        elif opcode == 18:
            if (fr & 0b0001) == 0:
                pc = Imm16
        
        elif opcode == 19:
            if fr &0b0010:
                pc = Imm16
        
        elif opcode == 20:
            if (fr & 0b0100 >> 2) != (fr & 0b1000 >> 3):
                pc = Imm16

        elif opcode == 26:
            if (fr & 0b0001) == 0 and (fr & 0b0100 >> 2) == (fr & 0b1000 >> 3):
                pc = Imm16
        
        elif opcode == 27:
            if (fr & 0b0010) == 0 and (fr & 0b0001) == 0:
                pc = Imm16

        else:
            raise ValueError("Unknown opcode", opcode)

    # 8 bit
    for i in range(len(registers)):

        while registers[i] >= 256:
            registers[i] -= 256

        while registers[i] < 0:
            registers[i] = 256 - abs(registers[i])
```

Running the program, we're prompted for 3 bytes of user input \(the "key"\).

```text
➜  ARC6969 python3 arc6969.py
Hello fellow komrade.
Wanna capture the flag?
Enter the key: 
```

After entering the key, some scrambled text is printed.

```text
➜  ARC6969 python3 arc6969.py
Hello fellow komrade.
Wanna capture the flag?
Enter the key: Number of bytes: 3
Byte: 0
Byte: 0
Byte: 0
dL@CLòaï*õ99ýNO;ý8NüÿN:üQQý(
```

This probably means our key is wrong. Hmm... let's reverse engineer the program to understand what's going on. Running the program again, this time uncommenting all the print statements, we can track the program's execution.

First, R4 is cleared by AND-ing with 0. Then, the three bytes of user input are stored in R1, R0 and R2 respectively.

```text
ARITHMETIC; opcode: 11; Rx: 4; Ry: 4; Rz/Imm8: 0
IO; Rx: 1; Imm3: 6
Byte: 0
IO; Rx: 0; Imm3: 6
Byte: 0
IO; Rx: 2; Imm3: 6
Byte: 0
```

I found that after receiving the 3 bytes of input, the program repeatedly performs the following loop:

```text
MEMORY OPERATION; opcode: 14; Rx: 6; Ry: 7; Rz: 8
ARITHMETIC; opcode: 12; Rx: 9; Ry: 6; Rz/Imm8: 12
ARITHMETIC; opcode: 13; Rx: 10; Ry: 6; Rz/Imm8: 11
ARITHMETIC; opcode: 6; Rx: 6; Ry: 9; Rz/Imm8: 10
ARITHMETIC; opcode: 0; Rx: 6; Ry: 6; Rz/Imm8: 1
ARITHMETIC; opcode: 8; Rx: 6; Ry: 6; Rz/Imm8: 0
ARITHMETIC; opcode: 2; Rx: 6; Ry: 6; Rz/Imm8: 2
IO; Rx: 6; Imm3: 7
OUTPUT: 100
ARITHMETIC; opcode: 1; Rx: 8; Ry: 8; Rz/Imm8: 1
ARITHMETIC; opcode: 1; Rx: 8; Ry: 8; Rz/Imm8: 0
ARITHMETIC; opcode: 1; Rx: 4; Ry: 4; Rz/Imm8: 1
COMPARISON; opcode: 5; Rx: 4; Ry/Imm8: 31
JUMP; opcode: 18; Imm16: 910
```

We can now translate this to the following pseudocode:

```text
R11 = 2
R12 = 6
R4 = R4 & 0
R1, R0, R2 = SERIAL INPUT
---
DO
    R6 = [R7 R8]
    R9 = R6 << R12
    R10 = R6 >> R11
    R6 = R9 | R10
    R6 = R6 + R1
    R6 = R6 ^ R0
    R6 = R6 - R2
    OUTPUT R6
    R8 = R8 + 1
    R4 = R4 + 1
WHILE R4 != 31
```

We can see that the 3-byte key is essentially used to perform the addition, XOR, and subtration operations on each byte of the flag. The loop continues until all 31 bytes of the flag are printed.

```text
R6 = R6 + R1
R6 = R6 ^ R0
R6 = R6 - R2
```

Entering the key 0, 0, 0 gives us the "original" values. We can then bruteforce the key:

```python
import itertools

key_chars = [x for x in range(256)]
possible = list(itertools.product(key_chars, repeat=3))

flag = [100, 76, 64, 67, 76, 242, 97, 239, 42, 245, 2, 57, 57, 253, 78, 79, 59, 253, 56, 78, 252, 4, 255, 4, 78, 58, 252, 81, 81, 253, 40]

i = 0

for key in possible:

    result = ''
    for flag_char in flag:
        decoded = (((((flag_char + key[0]) % 256) ^ key[1]) % 256) - key[2]) % 256
        result += chr(decoded)

    if 'yauzactf' in result.lower():
        print(result)

    i += 1
    if i % 100000 == 0:
        print("Progress:", i / len(possible))
```

![](../.gitbook/assets/image%20%2867%29.png)

The flag is `YauzaCTF{H3ll0_fr0m_1969_k1dd0}`.

