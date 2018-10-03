<?php
/**
 * Server stateless cookie based PHP session.
 *
 * How to Use: require_once() this file. Change KEY before using this.
 *
 * Requirement: PHP 7.1 and up, openssl for encryption.
 *
 * HUGE WARNING: You MUST set your own super secret master key.
 * i.e. Set $this->key of your own.
 *
 * WARNING: Data is protected by encryption. However once session data
 * is stolen, attackers can keep stolen session as long as they want.
 * i.e. No server side protection unless you have it in your app.
 *
 * WARNING: Session data is not locked. i.e. Race condition can break
 * your session data just like memcached session handler without lock.
 *
 * - You can store session data only up to 2KB.
 * - Data encryption is automatically updated by RENEW period.
 * - Old(expired by session.gc_maxlifetime) session data cannot be exploited, but remember
 *   active session can be stolen and attackers can exploit it as long as they want.
 *   i.e. You must have some kind of protection in your app such as invalidate
 *   sessions have too long lifetime.
 * - Server clocks must be in sync. i.e. time() must return the same timestamp for
 *   the moment. Up to 1 sec difference is allowed.
 */
class SessionCookie implements SessionHandlerInterface{
    // HUGE WARNING: Set crypt strong random key!!!!
    // e.g. Random key like bin2hex(random_bytes(32));
    private $key;

    // Cookies used. These are validated with psvk
    private $cookies = ['psdat', 'psct', 'pskey', 'psts', 'psiv'];

    // Cookie params
    private $cookie_lifetime;
    private $cookie_path;
    private $cookie_domain;
    private $cookie_secure;
    private $cookie_httponly;
    // Other session settings
    private $gc_maxlifetime;
    private $use_exception;

    // KEY renewal period.
    // Note: Attackers can exploit stolen session up to session.gc_maxlifetime + RENEW.
    const RENEW = 60;

    // Tapering detection.
    const TAMPER = true;

    function __construct($key = null, $use_exception = true) {
        assert(is_null($key) || (is_string($key) && strlen($key) > 20));
        assert(is_bool($use_exception));

        $env_key = getenv('PHP_SESSION_COOKIE_KEY');
        assert(is_null($env_key) || (is_string($env_key) && strlen($env_key) > 20));

        $this->key = $key ?? $env_key ?? null;
        if (!$this->key) {
            throw new InvalidArgumentException('Cookie based session cannot work without secret master key.');
        }

        $this->use_exception = $use_exception;

        $this->cookie_lifetime = ini_get('session.cookie_lifetime');
        $this->cookie_path     = ini_get('session.cookie_path');
        $this->cookie_domain   = ini_get('session.cookie_domain');
        $this->cookie_secure   = ini_get('session.cookie_secure');
        $this->cookie_httponly = ini_get('session.cookie_httponly');

        $this->gc_maxlifetime = ini_get('session.gc_maxlifetime');
    }

    function open($path, $sess_name)
    {
        // Implement proper lock mechanism if you want to avoid race conditions.
        // e.g. Lock is required to count access counts correctly, etc.
        // Acquire lock here.
        // Lock must be shared across web servers.
        return true;
    }


    function close()
    {
        // Implement proper lock mechanism if you want to avoid race conditions.
        // e.g. Lock is required to count access counts correctly, etc.
        // Release lock here.
        // Lock must be shared across web servers.
        return true;
    }


    function read($sid)
    {
        if (!$this->checkCookie()) {
            return '';
        }

        if ($_COOKIE['psts'] + $this->gc_maxlifetime < time()) {
            $this->resetCookie();
            return '';
        }

        $data = $this->decrypt();
        return $data;
    }


    function write($sid, $data)
    {
        if ($_COOKIE['psts'] + self::RENEW < time()) {
            $this->updateCookie();
        }
        if (strlen($data) > 2048) {
            throw new LengthException('You cannot save too large session data over 2KB.');
            $this->resetCookie();
            $this->setDataCookie('');
            return true;
        }
        $edata = $this->encrypt($data);
        $this->setDataCookie($edata);
        return true;
    }


    function destroy($sid)
    {
        $this->resetCookie(true);
        $this->setDataCookie('');
    }


    function gc($maxlifetime)
    {
        return 0;
    }


    function create_sid()
    {
        return sha1(random_bytes(32));
    }


    function validate_sid($sid)
    {
        return true;
    }


    function update_timestamp($sid, $data)
    {
        assert(isset($_COOKIE['psts']));

        if ($_COOKIE['psts'] + self::RENEW < time()) {
            $ts = (string)time();
            $this->setcookie('psts', $ts);
            $_COOKIE['psts'] = $ts;
            $edata = $this->encrypt($data);
            $this->setDataCookie($edata);
        }
        return true;
    }


    private function setcookie($name, $data)
    {
        setcookie($name, $data,
                  $this->cookie_lifetime,
                  $this->cookie_path,
                  $this->cookie_domain,
                  $this->cookie_secure,
                  $this->cookie_httponly);
    }

    private function detectedAttack($error_msg)
    {
        $this->resetCookie(true);
        $this->setDataCookie('');
        if (!self::TAMPER) {
            return;
        }
        if ($this->use_exception) {
            throw new InvalidArgumentException($error_msg);
        } else {
            trigger_error($error_msg);
        }
    }


    private function getEnckey()
    {
        assert(isset($_COOKIE['psct']));
        assert(isset($_COOKIE['psts']));
        assert(isset($_COOKIE['pskey']));

        $ct  = $_COOKIE['psct'] ?? 0;
        $ts  = $_COOKIE['psts'] ?? 0;
        $key = $_COOKIE['pskey'] ?? '';
        $enckey = hash_hkdf('sha256',
                            $this->key,
                            0,
                            $ts.'&'.$ct,
                            $key);
        return $enckey;
    }


    private function encrypt($data)
    {
        assert(isset($_COOKIE['psdat']));
        assert(isset($_COOKIE['psiv']));

        $enckey = $this->getEnckey();
        $iv     = base64_decode($_COOKIE['psiv']);
        $edata  = openssl_encrypt($data, 'AES-256-CBC', $enckey, 0, $iv);

        if ($edata === false) {
            return '';
        }
        return base64_encode($edata);
    }


    private function decrypt()
    {
        assert(isset($_COOKIE['psdat']));
        assert(isset($_COOKIE['psiv']));

        $data   = base64_decode($_COOKIE['psdat']);
        if (!$data) {
            return '';
        }

        $enckey = $this->getEnckey();
        $iv     = base64_decode($_COOKIE['psiv']);
        $sdata  = openssl_decrypt($data, 'AES-256-CBC', $enckey, 0, $iv);
        if ($sdata !== false) {
            return $sdata;
        }
        return '';
    }


    private function checkCookie()
    {
        if (empty($_COOKIE['pskey']) ||
            empty($_COOKIE['psiv']) ||
            empty($_COOKIE['psts']) ||
            empty($_COOKIE['psct']) ||
            empty($_COOKIE['psdat']) ||
            empty($_COOKIE['psvk'])
        ) {
            $this->resetCookie(true);
            return false;
        }

        foreach ($this->cookies as $c) {
            $tmp[] = $_COOKIE[$c];
        }
        $cookies = join('&', $tmp);
        if (!hash_equals($_COOKIE['psvk'], hash_hmac('sha256', $cookies, $this->key))) {
            $this->detectedAttack('Attack detected: Invalid key info.');
            return false;
        }

        $maxlifetime = ini_get('session.gc_maxlifetime');
        if ($_COOKIE['psts'] + $maxlifetime < time()) {
            $this->resetCookie();
            return false;
        }

        return true;
    }


    private function resetCookie($clear_ct = false)
    {
        $this->setBaseCookie($clear_ct);
    }


    private function updateCookie()
    {
        $this->setBaseCookie(false);
    }


    private function setBaseCookie($clear_ct)
    {
        $key = base64_encode(random_bytes(32));
        $iv  = base64_encode(random_bytes(16));
        $ts  = (string)time(); // There is slight chance for race, but ignorable.
        $this->setcookie('pskey',  $key);
        $this->setcookie('psiv',   $iv);
        $this->setcookie('psts',   $ts);
        $this->setcookie('psdat',  '');
        $_COOKIE['pskey'] = $key;
        $_COOKIE['psiv']  = $iv;
        $_COOKIE['psts']  = $ts;
        $_COOKIE['psdat'] = '';
        if ($clear_ct || empty($_COOKIE['psct'])) {
            $this->setcookie('psct',   $ts);
            $_COOKIE['psct']  = $ts;
        }
    }


    private function setDataCookie($edata) {
        assert(isset($_COOKIE['psct']));
        assert(isset($_COOKIE['pskey']));
        assert(isset($_COOKIE['psiv']));
        assert(isset($_COOKIE['psts']));

        $this->setcookie('psdat', $edata);
        $_COOKIE['psdat'] = $edata;
        foreach($this->cookies as $c) {
            $tmp[] = $_COOKIE[$c];
        }
        $cookies = join('&', $tmp);
        $vk = hash_hmac('sha256', $cookies, $this->key);
        $this->setcookie('psvk', $vk);
        $_COOKIE['psvk'] = $vk;
    }
}
