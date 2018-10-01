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

## Security

* Cookie based session (and other client side sessions as well) is weak to session highjack compare to server side sessions.
* There is no session data locking. Race condition can happen and some session data can lost.
* Session data cookie is protected by AES256
* Encryption key is protected by HKDF derived key with FS/PFS in mind.
* $_COOKIE['psct'] holds session data creation time. It can be trusted when decryption succeeds.
* Sessions cannot live longer than session.gc_maxlifetime.
* Server cannot invalidate stolen sessions. i.e. Server based session can delete session data at server side, but not client side stolen session cookies. You can try to delete cookie, but it's up to client.
* Attacker (session hijackers) can keep active session by accessing before expiration defined by session.gc_maxlifetime. The same applies to server side sessions, but admin can remove server side session data.

Remember that cookie based session is only suitable for **low security** requirement.

## Limitations

* Session data max is 2KB. It's cookie.
* Cookie does not have lock mechanism. Therefore, no data lock.
* Server clocks must be synced. i.e. time() must return the same value for the moment.

## How it works

* HKDF with SHA256 uses internal secret key as IKM and external COOKIE['key'] as "salt", COOKIE['psts'] and COOKIE['psct'] as "info" to derivate AES256 encryption/decryption key.
* AES256 is used to encrypt session data (COOKIE['psdat']). COOKIE['iv'] is used as IV.
* Encryption key is updated every 60 sec.
* Session lasts up to session.gc_maxlifetime.
* Session INI settings such session.cookie_httponly is honored.

Besides this has 2KB session data max and unlocked session data, it works like
other session data save handlers. Enjoy with applications have low security requirements!
