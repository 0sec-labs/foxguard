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

// Literal include path — not a dynamic inclusion.
include "vendor/autoload.php";

// Pure-literal double-quoted SQL string — no interpolation, so not injectable.
mysqli_query($conn, "SELECT * FROM users WHERE active = 1");

// URL sourced from the environment is not request-controlled.
file_get_contents(getenv('SAFE_URL'));

// Shell argument is escaped via escapeshellcmd()/escapeshellarg().
exec(escapeshellcmd($x));
system(escapeshellarg($y));

// Pattern contains the letter "e" in the body but no /e modifier.
preg_replace('/foo/i', 'replacement', $name);
preg_replace('/header/', 'replacement', $name);
