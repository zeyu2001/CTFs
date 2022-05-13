# OTP Vault

This was a mobile challenge. We are faced with a screen that asks for an OTP.

After decompiling the APK, I saw the following in the source code.

`n.s='JJ2XG5CIMFRWW2LOM4',n.url='http://congon4tor.com:7777',n.token='652W8NxdsHFTorqLXgo=',n.getFlag=function(){var e,o;return t.default.async(function(u){for(;;)switch(u.prev=u.next){case 0:return u.prev=0,e={headers:{Authorization:'Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN'}}`

It seems a request is made to `http://congon4tor.com:7777` to fetch the flag after the OTP check is successful. We could skip the check and directly fetch the URL ourselves.

We can successfully obtain the flag using the Bearer token included in the source code.

```http
GET /flag HTTP/1.1
Host: congon4tor.com:7777
Authorization: Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN
Connection: close

```
