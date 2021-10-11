---
description: TCP covert channel using Morse Code
---

# Space Noise

## Description

We just intercepted a secret transmission from the Secret Space Agency, but the traffic looks really weird... Wireshark shows so much red! Can you help us to figure out what's going on?

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

{% file src="../../.gitbook/assets/space_noise.pcap" %}
space_noise.pcap
{% endfile %}

## Solution

We are provided with a PCAP file containing packets sent between 192.168.1.1 and 192.168.1.2.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 8.19.22 PM.png>)

Let's find some patterns! 

First, notice that the SYN-PSH pair is sent at regular intervals. Perhaps this is a delimiter of sorts. The SYN packet is sent from 192.168.1.1 to 192.168.1.2, while the PSH packet is sent from 192.168.1.2 to 192.168.1.1.

Next, in between the SYN-PSH pairs, there are RST and URG packets. Since only two different packets are used, binary and morse code comes to mind. 

Notice that there are _up to_ 5 packets between the SYN-PSH pairs. If this was a 5-bit encoding, it wouldn't make much sense for the number of bits to vary from 1 to 5. In [morse code](http://sckans.edu/\~sireland/radio/code.html), however, alphanumeric characters are represented by _up to_ 5 dots and slashes.

### The Protocol

This is a covert TCP channel, implemented using morse code. The protocol is as follows:

* RST = .
* URG = -
* SYN = I have finished sending a character.
* PSH = I acknowledge this character. Send the next character.

Decoding the morse code gives the flag in hex.

### Solve

The following script implements the solution.

```python
from Crypto.Util.number import long_to_bytes
from scapy.all import *

packets = rdpcap("space_noise.pcap")

FLAGS = {
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80
}

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

morse_code = ''

for p in packets:
    if p['TCP'].flags == 'R':
        morse_code += '.'
    elif p['TCP'].flags == 'U':
        morse_code += '-'
    elif p['TCP'].flags == 'S':
        morse_code += ' '

message = ''
curr = ''

print(morse_code)

for char in morse_code:

    if char != ' ':
        curr += char

    else:
        for char in MORSE_CODE_DICT:
            if MORSE_CODE_DICT[char] == curr:
                message += char
            
        curr = ''

print(message)
print(long_to_bytes(int(message, 16)).decode())
```

The flag is `STC{I believe that this Nation should commit itself to achieving the goal, before this decade is out, of landing a man on the Moon and returning him safely to Earth.}`

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 9.35.19 PM.png>)
