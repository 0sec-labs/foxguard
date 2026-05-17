<?php
// PHP safe fixture — should not trigger built-in PHP rules.

$userId = (int) $userInput;
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$userId]);

$allowedCommand = 'status';
error_log($allowedCommand);

$data = json_decode($json, true);

$allowed = __DIR__ . '/templates/home.php';
echo basename($allowed);

$hash = password_hash($password, PASSWORD_DEFAULT);

$apiKey = getenv('API_KEY');
$url = 'https://api.example.com/health';
echo parse_url($url, PHP_URL_HOST);

$name = filter_input(INPUT_GET, 'name', FILTER_SANITIZE_STRING);
preg_replace('/pattern/', 'replacement', $name);
