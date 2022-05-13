# No Space Between Us

There was a Discord bot that would tell "stories". The stories contained [zero-width space](https://en.wikipedia.org/wiki/Zero-width\_space) (ZWSP), which were used to encode binary. Basically, the ZWSP was either `\xe2\x80\x8c\x20` (which represented a 0), or `\xe2\x80\x8d\x20` (which represented a 1).

The following script automates the process of DM-ing the bot and decoding the text.

```python
import requests
import time

i = 0

flag = ''

while True:
    res = ''

    r = requests.post(
        'https://discord.com/api/v9/channels/CHANNELID/messages',
        headers={
            'Authorization': 'TOKEN',
        },
        json={
            "content":f"story {i}",
            "tts":False
        }
    )

    time.sleep(1)

    r = requests.get(
        'https://discord.com/api/v9/channels/CHANNELID/messages',
        headers={
            'Authorization': 'TOKEN',
        }
    )

    latest = r.json()[0]
    data = bytes(latest['content'], 'utf-8')
    print(data)

    low = 0
    high = 4
    while low < len(data):
        section = data[low:high]
        if section == b"\xe2\x80\x8c\x20":
            res += '0'
        elif section == b"\xe2\x80\x8d\x20":
            res += '1'

        low += 1
        high = low + 4

    print(res, int(res, 2), chr(int(res, 2)))

    if flag and chr(int(res, 2)) == '}':
        break

    else:
        flag += chr(int(res, 2))

    i += 1

    print(flag)
```
