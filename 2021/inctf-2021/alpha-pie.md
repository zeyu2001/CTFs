---
description: Breadth-first Search algorithm for a fun programming task
---

# Alpha Pie

## Challenge

We have created a mini game to test your skills. Go grab the flag!!

**authors :** careless\_finch, malf0y

`nc misc.challenge.bi0s.in 1337`

## Solution

Here are the rules of the challenge:

![](../../.gitbook/assets/image%20%2849%29.png)

This could be solved by performing a breadth-first search \(BFS\) on all the possible moves. The problem with a depth-first search \(DFS\) - which I tried at first - was that we could get a solution, but it wouldn't be the _best_ solution \(it will exceed the maximum number of moves\) , and finding the _best_ solution would take too long on later levels.

But even on a BFS, the lower layers would eventually get too big since each game state would have many possible moves. To solve this, I filtered out those moves that heuristically "don't make sense".

In particular, I implemented this function that computes the "difference" between the current grid and the target grid. This is essentially the sum of the absolute differences of the _x_ and _y_ coordinates between the grids.

```python
def compute_difference(self, other_grid):
    result = 0
    values = []
    for row in self.grid:
        values += [x for x in row if x != '0']
    
    for value in values:
        x1, y1 = self.get_coords(value)
        x2, y2 = other_grid.get_coords(value)

        result += abs(x1 - x2) + abs(y1 - y2)

    return result
```

Heuristically, if making a move increases this difference, then that move is worse than one that decreases it. After generating all the possible moves, a threshold is applied at each layer to filter these bad moves.

Here's the final solve script:

```python
from pwn import *
from copy import deepcopy as copy
from pprint import pprint


class Grid:
    def __init__(self, grid, path=[]):
        self.grid = grid
        self.path = path

    def make_move(self, move):
        """
        move: [current-x-cord, current-y-cord, to-x-cord, to-y-cord]
        """
        curr_x, curr_y, to_x, to_y = move
        tmp = self.grid[curr_y][curr_x]
        self.grid[curr_y][curr_x] = '0'

        if self.grid[to_y][to_x] == '0':
            self.grid[to_y][to_x] = tmp
            self.path.append(move)
        else:
            raise ValueError("Destination is not empty")

    def get_possible_moves(self):

        result = []

        for y in range(len(self.grid)):
            for x in range(len(self.grid)):

                if self.grid[y][x] != '0':

                    if y != len(self.grid) - 1 and self.grid[y+1][x] == '0':
                        result.append((x, y, x, y + 1))

                    if y != 0 and self.grid[y-1][x] == '0':
                        result.append((x, y, x, y - 1))

                    if x != len(self.grid) - 1 and self.grid[y][x+1] == '0':
                        result.append((x, y, x + 1, y))

                    if x != 0 and self.grid[y][x-1] == '0':
                        result.append((x, y, x - 1, y))
        
        return result

    def get_coords(self, value):
        for y in range(len(self.grid)):
            for x in range(len(self.grid)):
                if self.grid[y][x] == value:
                    return (x, y)

    def compute_difference(self, other_grid):
        result = 0
        values = []
        for row in self.grid:
            values += [x for x in row if x != '0']
        
        for value in values:
            x1, y1 = self.get_coords(value)
            x2, y2 = other_grid.get_coords(value)

            result += abs(x1 - x2) + abs(y1 - y2)

        return result

    def copy(self):
        return Grid(copy(self.grid), copy(self.path))

    def __eq__(self, other_grid):
        return self.grid == other_grid.grid

    def __str__(self):
        to_ret = '+' + '-' * (len(self.grid) * 4 - 1) + '+\n'
        for row in self.grid:
            to_ret += '| ' + ' | '.join(row) + ' |' + '\n'
        to_ret += '+' + '-' * (len(self.grid) * 4 - 1) + '+\n'
        return to_ret


def solve(grid, target_grid):

    print("Solving...")
    
    layer = [grid]
    done = False
    visited = []

    while not done:
        next_layer = []

        curr_min_diff = 10000000000
        curr_best_grid = None

        for grid in layer:
            
            if grid in visited:
                continue

            elif grid == target_grid:
                print("Solved!")
                return grid.path

            possible_moves = grid.get_possible_moves()
            visited.append(grid)

            for move in possible_moves:
                new_grid = grid.copy()
                new_grid.make_move(move)

                diff = new_grid.compute_difference(target_grid)
                if diff < curr_min_diff:
                    curr_best_grid = new_grid
                    curr_min_diff = diff

                next_layer.append(new_grid)

        treshold = curr_min_diff
        print("Threshold:", treshold)

        if treshold <= 10:
            next_layer = [x for x in next_layer if x.compute_difference(target_grid) <= treshold]

        else:
            next_layer = [curr_best_grid]
        
        layer = next_layer


conn = remote("misc.challenge.bi0s.in", 1337)

print(conn.recv().decode())
print(conn.recv().decode())
conn.send(b'y\n')

print(conn.recv().decode())
received = conn.recv().decode()
print(received)

level = 0
while True:
    grid = []
    target_grid = []

    for line in received.splitlines():
        if line.startswith('|'):
            row = []
            data = [x.strip() for x in line.split('|') if x and not x.isspace()]

            grid.append(data[:len(data) // 2])
            target_grid.append(data[len(data) // 2:])

    grid = Grid(grid)
    target_grid = Grid(target_grid)

    print("Level:", level)
    print(grid)
    print(target_grid)

    solved = solve(grid, target_grid)
    # print(solved, len(solved))
    
    for move in solved:
        
        print("Sending move...")
        curr_x, curr_y, to_x, to_y = move
        conn.send(f"{curr_y},{curr_x},{to_y},{to_x}\n")
        received = conn.recv().decode()
        print(received)
        received = conn.recv().decode()
        print(received)
    
    level += 1

    if level == 9:
        break

print(conn.recv().decode())
```

After successfully solving nine levels, we get the flag.

![](../../.gitbook/assets/image%20%2852%29.png)

