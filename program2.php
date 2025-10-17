<?php
declare(strict_types=1);

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax'
]);

session_start();

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(string $token): bool {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function validate_int_id($value): ?int {
    if ($value === null) return null;
    $options = ['options' => ['min_range' => 1]];
    $int = filter_var($value, FILTER_VALIDATE_INT, $options);
    return ($int === false) ? null : (int)$int;
}

function validate_uuid(string $value): ?string {
    $value = trim($value);
    if (preg_match('/^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-4[0-9a-fA-F]{3}\-[89abAB][0-9a-fA-F]{3}\-[0-9a-fA-F]{12}$/', $value)) {
        return $value;
    }
    return null;
}

$dsn = 'mysql:host=127.0.0.1;dbname=your_database;charset=utf8mb4';
$dbUser = 'your_db_user';
$dbPass = 'your_db_password';

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (PDOException $e) {
    error_log('PDO connection failed: ' . $e->getMessage());
    http_response_code(500);
    echo 'Internal server error';
    exit;
}

$user = null;
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $posted_csrf = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($posted_csrf)) {
        $errors[] = 'Invalid request (CSRF).';
    } else {
        $raw_id = $_POST['user_id'] ?? '';
        $int_id = validate_int_id($raw_id);
        $uuid = is_string($raw_id) ? validate_uuid($raw_id) : null;

        if ($int_id !== null) {
            $sql = 'SELECT user_id, username, email FROM users WHERE user_id = :id LIMIT 1';
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':id', $int_id, PDO::PARAM_INT);
            $stmt->execute();
            $user = $stmt->fetch();
        } elseif ($uuid !== null) {
            $sql = 'SELECT id AS user_id, username, email FROM users WHERE id = :uuid LIMIT 1';
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(':uuid', $uuid, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch();
        } else {
            $errors[] = 'Invalid User ID format.';
        }

        if ($user === false) {
            $user = null;
            $errors[] = 'User not found.';
        }
    }
}
?>

<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Secure User Lookup</title>
</head>
<body>
<h1>Lookup User</h1>

<?php if (!empty($errors)): ?>
<div role="alert">
<ul>
<?php foreach ($errors as $err): ?>
<li><?php echo htmlspecialchars($err, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></li>
<?php endforeach; ?>
</ul>
</div>
<?php endif; ?>

<form method="post" action="">
<label for="user_id">User ID (int or UUID):</label>
<input id="user_id" name="user_id" type="text" required maxlength="100" pattern="[0-9\-a-fA-F]+" />
<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8'); ?>">
<button type="submit">Lookup</button>
</form>

<?php if ($user): ?>
<h2>User info</h2>
<ul>
<li>User ID: <?php echo htmlspecialchars((string)$user['user_id'], ENT_QUOTES, 'UTF-8'); ?></li>
<li>Username: <?php echo htmlspecialchars((string)$user['username'], ENT_QUOTES, 'UTF-8'); ?></li>
<li>Email: <?php echo htmlspecialchars((string)$user['email'], ENT_QUOTES, 'UTF-8'); ?></li>
</ul>
<?php endif; ?>
</body>
</html>