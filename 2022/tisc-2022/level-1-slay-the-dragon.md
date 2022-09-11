# Level 1 - Slay The Dragon

## Description

> The recently launched online RPG game "Slay The Dragon" has been hot topic in the online gaming community of late, due to a seemingly impossible final boss. Amongst the multiple tirades against the forementioned boss, much controversy has been brewing due to rumors of the game being a recruitment campaign for PALINDROME, the cybercriminal organisation responsible for recent cyberattacks on Singapore's critical infrastructure.
>
> You are tasked to find a way to beat (hack) the game and provide us with the flag (a string in the format TISC{xxx}) that would be displayed after beating the final boss. Your success is critical to ensure the safety of Singapore's cyberspace, as it would allow us to send more undercover operatives to infiltrate PALINDROME.
>
> To aid in your efforts, we have managed to obtain the source code of the game for you. We look forward to your success!
>
> You will be provided with the following:
>
> 1. Source code for game client/server (Python 3.10.x)
> 2. Game client executable (Compiled with PyInstaller)
> 3. Highly recommended that you run it in a modern terminal (not cmd.exe) for the optimal experience:
>    * Windows: Windows Terminal or ConEmu recommended.
>    * Linux: the default terminal should be fine.
>
> Note: If you'd like to make any modifications to the client, we'd strongly suggest modifying the source code and running it directly. The game client executable has been provided purely for your convenience in checking out the game.
>
> Host: chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg&#x20;
>
> Port: 18261

{% file src="../../.gitbook/assets/slay_the_dragon.zip" %}

## Solution

This challenge revolved around a game client and server, and the exploit relied upon the insecure use of client-side validation over server-side validation.

Sidenote - nice ASCII art!

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-12 at 12.06.12 AM.png" alt=""><figcaption></figcaption></figure>

### Infinite Gold Exploit

The game provides a way to earn gold through mining, which can be spent on swords (which boost our attacks) and potions (which heal our character). This seemed like a great place to start, since having an unlimited amount of potions to heal our character would probably help us to beat the game.

This turned out to be useless - the last boss had a one-hit-kill attack, and we could not buy more than one sword. If we could buy unlimited swords, this exploit would have allowed us to beat the boss by using a one-hit-kill attack of our own.

Nonetheless, this is an interesting vulnerability to discuss!

First of all, there was a chance of "dying to a creeper" when mining for gold. However, this was implemented entirely on the client-side and can be commented out.

```python
def run(self):
    if random() <= CREEPER_ENCOUNTER_CHANCE:
        self.__die_to_creeper()
    self.__mine_safely()

def __die_to_creeper(self):
    screens.display_creeper_screen()
    screens.display_game_over_screen()
    self.client.exit()

def __mine_safely(self):
    screens.display_working_screen()
    self.client.send_command(Command.WORK)
```

Further, there was an arbitrary slowdown implemented by the `display_working_screen` function, which `sleep`s  for a period of time. This is meant to prevent doing exactly what we hope to do - spamming the mining functionality to gain unlimited gold.

```python
def display_working_screen():
    clear_screen()
    print("\n\n\n\n\n\n")
    print(f"{'so we back in the mine...': ^80}")
    sleep(1)
    print(f"{'got our pickaxe swinging from,': ^80}")
    sleep(1)
    print(f"{'side to side...': ^80}")
    sleep(1)
    print(f"{'side, side to side.': ^80}")
    sleep(2)
```

Once again, this is entirely client-side and we could comment out the call to this function entirely.

### Infinite Moves Exploit

After finding out that the previous exploit was useless unless we could have unlimited swords, I tried looking for ways to end the battle in one turn (since the last boss always kills us on the first turn). This required us to look deeper into how the game server processes commands.

First of all, we need to understand how the client-server traffic is actually encoded. Thankfully, this is pretty simple - all traffic is base64-encoded and each command is delimited by the `EOF_MARKER`.

```python
def recv() -> str:
    return decode(NetClient.__recvuntil(EOF_MARKER))
```

The `EOF_MARKER` is defined in `config.py`, and is simply the pound sign.

```python
######################
#   NETWORK CONFIG   #
######################

# Protocol
EOF_MARKER = "#"
```

When receiving a command from the client through `recv_command_str()`, the server processes the command and stores it in `self.history.commands`.

```python
while True:
    self.history.log_commands_from_str(self.server.recv_command_str())

    match self.history.latest:
        case Command.ATTACK | Command.HEAL:
            self.history.log_command(Command.BOSS_ATTACK)
        case Command.VALIDATE:
            break
        case Command.RUN:
            return
        case _:
            self.server.exit(1)

match self.__compute_battle_outcome():
    case Result.PLAYER_WIN_BATTLE:
        self.__handle_battle_win()
        return
    case Result.BOSS_WIN_BATTLE:
        self.server.exit()
    case _:
        self.server.exit(1)
```

The server then checks the **latest** command - if the latest command is `ATTACK` or `HEAL`, then the boss gets to attack and this attack is stored in `self.history.commands`. If it is `VALIDATE`, then it will process all commands stored in `self.history.commands` and compute the battle result.

```python
def __compute_battle_outcome(self) -> Optional[Result]:
    for command in self.history.commands:
        match command:
            case Command.ATTACK:
                self.boss.receive_attack_from(self.player)
                if self.boss.is_dead:
                    return Result.PLAYER_WIN_BATTLE
            case Command.HEAL:
                self.player.use_potion()
            case Command.BOSS_ATTACK:
                self.player.receive_attack_from(self.boss)
                if self.player.is_dead:
                    return Result.BOSS_WIN_BATTLE
    return None
```

But if we take a look at `log_commands_from_str`, it becomes apparent that the server could receive more than one command at a time.

```python
def log_commands_from_str(self, commands_str: str):
    self.log_commands(
        [Command(command_str) for command_str in commands_str.split()]
    )
```

We could therefore send any number of commands before a final `VALIDATE` command, and all the commands will be processed without allowing the boss to attack.

The actual attack is simple - just base64-encode an `ATTACK ATTACK ATTACK ... ATTACK VALIDATE` string and send it to the server.

```python
from pwn import *
import base64
import json

conn = remote('chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg', 18261)


def send(data):
    conn.send(base64.b64encode(data.encode()) + b'#')


def recv():
    return base64.b64decode(conn.recvuntil(b'#')).decode()


def view_stats():

    send('VIEW_STATS')
    jsonData = json.loads(recv())
    return jsonData


def battle(ourAttack, ourHp):

    send('BATTLE')
    bossData = json.loads(recv())
    print(bossData)

    bossAttack = bossData['attack']
    bossHP = bossData['hp']

    toSend = ''

    while True:

        toSend += 'ATTACK '
        bossHP -= ourAttack

        if bossHP <= 0:
            break

    send(toSend + 'VALIDATE')

    recved = recv()
    if recved == 'VALIDATED_OK':
        return False
    elif recved == 'OBTAINED_FLAG':
        return recv()
    else:
        raise Exception(f"Unexpected response: {recved}")


def main():
    stats = view_stats()

    while not (res := battle(1, stats['hp'])):
        stats = view_stats()

    print(res)


main()
```

The flag is `TISC{L3T5_M33T_4G41N_1N_500_Y34R5_96eef57b46a6db572c08eef5f1924bc3}`.
