<?php
// This requires web server.
// e.g. php -S 127.0.0.1:8888

require_once __DIR__.'/php-session-cookie-handler.php';

$key = 'super secret master key'; // Or set $_ENV['PHP_SESSION_COOKIE_KEY']
$handler = new SessionCookie($key);
session_set_save_handler($handler);

session_start();
if (empty($_SESSION['count'])) {
    $_SESSION['count'] = 1;
} else {
    $_SESSION['count']++;
}

echo '<pre>';
var_dump($_SESSION, $_COOKIE, ini_get('session.save_handler'));

//session_regenerate_id(); // Testing regenerate. Regenerate is not needed for cookie based session.
//session_destroy(); // Testing destroy.
