# PHP Session Cookie Save Handler

This script uses cookie as session data storage.

Why I made this?  There are too many broken JWT based session.
It is useful for apps that require **low security**
since it does not consume server side resources.

If you need high security for sessions, use usual server side session storage.

* Requires: PHP 7.1, openssl

## Usage

```php
require_once 'php-session-cookie-handler.php';
$key = 'super secret master key'; // Or set $_ENV['PHP_SESSION_COOKIE_KEY']
$handler = new SessionCookie($key);
session_set_save_handler($handler);

session_start();
```

## WARNING

You must set your own self::KEY, otherwise session data is open to the world.

## Security

* Session data cookie is protected by AES256
* Encryption key is protected by HKDF with FS/PFS in mind.
* $_COOKIE['psct'] holds session data creation time. It can be trusted when decryption succeeds.

Remember that cookie based session is only suitable for **low security** requirement.

## Limitations

* Session data max is 2KB. It's cookie.
* Server cannot invalidate stolen sessions. i.e. Server based session can delete session data at server side.