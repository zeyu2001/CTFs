# L33t M4th

Math problems... but in words instead of numbers... and with l33t sp34k...

I used the `word2number` library to convert the words to numbers, a dictionary to map the l33t speak, and a bunch of if-else statements for the operators. Then, the result is calculated using `eval()`.

```python
from pwn import *
from word2number import w2n

conn = remote('chals3.umdctf.io', 6003)

mapping = {
    '1': 'i',
    '3': 'e',
    '0': 'o',
    '7': 't',
    '5': 's',
    '4': 'a',
    '$': 's',
}

conn.recv()
conn.send('\n')

done = False
received = ""

while not done:

    data = conn.recvuntil('What is RESULT').decode()

    # print(data)
    variables = []
    for line in data.split('\n')[1:-2]:
        line = line.split('=')[1][1:]
        line = ''.join([mapping[char] if char in mapping else char for char in line])

        words = line.split()
        # print(words)

        to_eval = ''

        number = ''
        for word in words:
            # print(number)
            if word == 'hundreed':
                word = 'hundred'

            if word == 'fourty':
                word = 'forty'

            if word == 'or':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '|'
                number = ''

            elif word == 'and':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '&'
                number = ''

            elif word == 'times':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '*'
                number = ''

            elif word == 'divided':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '//'
                number = ''

            elif word == 'Pius' or word == 'plus':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '+'
                number = ''

            elif word == 'MiNus' or word == 'minus':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '-'
                number = ''

            elif word == 'mod':
                to_eval += str(w2n.word_to_num(number))
                to_eval += '%'
                number = ''

            else:
                number += word + ' '

        to_eval += str(w2n.word_to_num(number))

        # print(to_eval)
        variables.append(eval(to_eval))

    # print(variables)

    result_line = data.split('\n')[-2]
    line = result_line.split('=')[1][1:]
    line = ''.join([mapping[char] if char in mapping else char for char in line])
    words = line.split()
    # print(words)

    curr_var = 0
    to_eval = ''
    for word in words:
        if 'var' in word:
            to_eval += str(variables[curr_var])
            curr_var += 1

        else:
            if word == 'or':
                to_eval += '|'

            elif word == 'and':
                to_eval += '&'

            elif word == 'times':
                to_eval += '*'

            elif word == 'divided':
                to_eval += '//'

            elif word == 'Pius' or word == 'plus':
                to_eval += '+'

            elif word == 'MiNus' or word == 'minus':
                to_eval += '-'

            elif word == 'mod':
                to_eval += '%'

    # print(to_eval)
    result = eval(to_eval)
    # print(result)

    conn.send(str(result))
    received = conn.recvuntil('more equations to go!\n').decode()
    print(received)

    if '0 more equations' in received:
        done = True
        print(conn.recv())

conn.close()
```

![Screenshot 2021-04-17 at 2.58.23 PM.png](:/3643c7f0c36b435885dadf14a8086849)

