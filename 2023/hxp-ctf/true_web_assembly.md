# true\_web\_assembly

## Description

> [https://board.asm32.info/asmbb-v2-9-has-been-released.328/](https://board.asm32.info/asmbb-v2-9-has-been-released.328/)
>
> From the post:
>
> * “AsmBB is very secure web application, because of the internal design and the reduced dependencies. But it also supports encrypted databases, for even higher security.”
> * “Download, install and hack”
>
> Yes

## Solution

The challenge is to attack the latest version of [AsmBB](https://asm32.info/fossil/asmbb/index), a web-based message board implemented entirely in x86 assembly. The provided Dockerfile builds the `asmbb` engine using the source files from the `asmbb` and `freshlib` repositories.

```docker
# Get source files for asmbb
RUN wget https://asm32.info/fossil/asmbb/tarball/4c91cddaec/asmbb-4c91cddaec.tar.gz -O asmbb.tar.gz && \
	/bin/bash -c "echo 'b1e621d1ae988b35e836ec9142ccc6ce6cf7c24a090c4d973894770a62fa4ddc asmbb.tar.gz' | sha256sum --check" && \
	tar -xf asmbb.tar.gz || true && \
	mv asmbb-* asmbb

# Get source files for freshlib
# AsmBB uses functions from freshlib
RUN wget https://fresh.flatassembler.net/fossil/repo/fresh/tarball/6636a57441/Fresh+IDE-6636a57441.tar.gz -O fresh.tar.gz && \
	/bin/bash -c "echo '5ba395b0e957536bd66abc572414085aab5f2a527d28214881bbba72ec53e00d fresh.tar.gz' | sha256sum --check" && \
	tar -xf fresh.tar.gz && \
	mv Fresh* Fresh

# Build the asmbb engine
RUN lib=/Fresh/freshlib TargetOS=Linux /fasm/fasm -m 200000 /asmbb/source/engine.asm /engine
```

{% hint style="info" %}
This writeup will be redacted until the vulnerabilities are fully fixed in AsmBB
{% endhint %}
