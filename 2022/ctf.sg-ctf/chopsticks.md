# Chopsticks

Both challenges are based on the [Chopsticks game](https://en.wikipedia.org/wiki/Chopsticks\_\(hand\_game\)), but with twists on the rules.

Here are the rules for the first game:

```
+-------------------------------------------------+
| Rules:                                          |
| This game is similar to the game Chopsticks:    |
|   en.wikipedia.org/wiki/Chopsticks_(hand_game)  |
|                                                 |
| * Each person starts with two boxes, with 1     |
|   feather.                                      |
| * If any box has at least 1 feather, it is live |
| * If any box has no feathers, it is dead        |
| * If any box contains more than 6 feathers, it  |
|   is dead, and has all its feathers taken out.  |
| * If a player has both boxes dead, the player   |
|   loses.                                        |
| * At each turn, a player can either:            |
|   * Attack: Add all feathers from one box to    |
|     another (their own or another player's)     |
|       * You can't attack to and from a dead box |
|   * Split: Split the feathers between their     |
|     own boxes.                                  |
|       * A split that results in one box having  |
|         one or zero feathers is not allowed.    |
|       * A split can only happen if both boxes   |
|         are live.                               |
| * Loops are disallowed                          |
|   * The game will prevent you from entering a   |
|     state already visited.                      |
+-------------------------------------------------+
```

And the second:

```
+-------------------------------------------------+
| Rules:                                          |
| This game is similar to the game Chopsticks:    |
|   en.wikipedia.org/wiki/Chopsticks_(hand_game)  |
|                                                 |
| * Each person starts with two boxes, with 1     |
|   feather.                                      |
| * If any box has at least 1 feather, it is live |
| * If any box has no feathers, it is dead        |
| * If any box contains more than 6 feathers, it  |
|   is dead, and has all its feathers taken out.  |
| * If a player has both boxes dead, the player   |
|   loses.                                        |
| * At each turn, a player can either:            |
|   * Attack: Add all feathers from one box to    |
|     another (their own or another player's)     |
|       * You can't attack to and from a dead box |
|   * Split: Split the feathers between their     |
|     own boxes.                                  |
|       * A split that results in one box having  |
|         zero feathers is not allowed.           |
|       * A split can happen if one of the boxes  |
|         is dead, meaning a split can revive a   |
|         box.                                    |
| * Loops are disallowed                          |
|   * The game will prevent you from entering a   |
|     state already visited.                      |
+-------------------------------------------------+
```

### Simple Solution

It seems like many teams managed to solve both challenges by pitting the bot against itself. Since this is a solved game, two equally maximizing bots playing against each other will likely lead to the first player winning.

I didn't think of that for some reason...

### Solving with Minimax

What I did was write my own bot to play against the server's bot. Since the server's bot was likely using a similar algorithm as mine, I just had to increase the minimax depth until my bot could perform sufficient lookaheads to play better than the server's bot.

Surprisingly I only needed a depth of 5 to win and didn't need to implement alpha-beta pruning since it was returning a result fast enough.

The evaluation score is 1000 if we win, -1000 if we lose, and the difference between the total number of our feathers and the total number of the opponent's feathers otherwise.

```python
def get_score(board, player, depth):
    """Use the minimax algorithm to search up to <depth>"""

    winner = get_winner(board)
    if winner:
        if winner == 1:     # Maximizing player
            return 1000
        else:
            return -1000

    if depth == 0:
        return board['A'] + board['B'] - board['C'] - board['D']
    
    attacks = available_attacks(board, player)
    splits = available_splits(board, player)
    if not attacks and not splits:
        return 0

    max_value = -1000
    min_value = 1000

    for attack in attacks:
        temp_board = board.copy()
        from_hand, to_hand = attack

        temp_board[to_hand] += temp_board[from_hand]
        if temp_board[to_hand] > 6:
            temp_board[to_hand] = 0     # die

        value = get_score(temp_board, 3 - player, depth - 1)

        if player == 1:
            # Maximizing player
            max_value = max(max_value, value)
        else:
            # Minimizing player
            min_value = min(min_value, value)
    
    for split in splits:
        temp_board = board.copy()
        left, right = split

        if player == 1:
            temp_board['A'] = left
            temp_board['B'] = right
        
        else:
            temp_board['C'] = left
            temp_board['D'] = right

        value = get_score(temp_board, 3 - player, depth - 1)
        
        if player == 1:
            # Maximizing player
            max_value = max(max_value, value)
        else:
            # Minimizing player
            min_value = min(min_value, value)

    if player == 1:
        return max_value
    else:
        return min_value
```

We also had to account for the fact that the sever prevents us from returning to a previously visited game state, so we will keep track of visited states on our end as well.

Sorry for the repeated and inefficient code, I was stressed and just trying to get it to work :cry:

```python
def get_best_move(board):
    
    # We are player 1
    
    attacks = available_attacks(board, 1)
    splits = available_splits(board, 1)

    max_value = -1000
    max_move = []

    for attack in attacks:
        temp_board = board.copy()
        from_hand, to_hand = attack

        temp_board[to_hand] += temp_board[from_hand]
        if temp_board[to_hand] > 6:
            temp_board[to_hand] = 0

        if temp_board in visited:
            continue

        value = get_score(temp_board, 2, DEPTH)

        if value > max_value:
            max_value = value
            max_move = ['attack', attack]

    for split in splits:
        temp_board = board.copy()
        left, right = split

        temp_board['A'] = left
        temp_board['B'] = right

        if temp_board in visited:
            continue

        value = get_score(temp_board, 2, DEPTH)

        if value > max_value:
            max_value = value
            max_move = ['split', split]

    return max_move
```
