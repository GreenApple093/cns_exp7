<?php
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');

$cookie_lifetime = 0;
$cookie_path = '/';
$cookie_domain = '';
$cookie_secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$cookie_httponly = true;
$cookie_samesite = 'Lax';

session_set_cookie_params([
    'lifetime' => $cookie_lifetime,
    'path' => $cookie_path,
    'domain' => $cookie_domain,
    'secure' => $cookie_secure,
    'httponly' => $cookie_httponly,
    'samesite' => $cookie_samesite
]);

session_name('DVWA_SESSID');
session_start();

function random_token(int $bytes = 32): string {
    return bin2hex(random_bytes($bytes));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    session_regenerate_id(true);
    $token = random_token(32);
    $_SESSION['dvwa_token'] = $token;
    $_SESSION['created_at'] = time();

    setcookie('dvwaSession', $token, [
        'expires' => 0,
        'path' => $cookie_path,
        'domain' => $cookie_domain,
        'secure' => $cookie_secure,
        'httponly' => true,
        'samesite' => $cookie_samesite
    ]);
}

$valid = false;
if (!empty($_COOKIE['dvwaSession']) && !empty($_SESSION['dvwa_token'])) {
    if (hash_equals($_SESSION['dvwa_token'], $_COOKIE['dvwaSession'])) {
        $valid = true;
    }
}

if (!$valid && isset($_COOKIE['dvwaSession'])) {
    session_regenerate_id(true);
    unset($_SESSION['dvwa_token']);
    setcookie('dvwaSession', '', [
        'expires' => time() - 3600,
        'path' => $cookie_path,
        'domain' => $cookie_domain,
        'secure' => $cookie_secure,
        'httponly' => true,
        'samesite' => $cookie_samesite
    ]);
}
?>