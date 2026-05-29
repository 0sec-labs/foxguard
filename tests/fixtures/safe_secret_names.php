<?php
// Benign names containing secret-keyword substrings, or low-signal
// keywords with env-sourced values. None should be flagged by
// php/no-hardcoded-secret after the word-boundary + value-gate fix.

// Substring false positives.
$author = "Pallets";
$authors = "core team";
$authenticated = "yes";
$authorizationScheme = "Bearer";
$tokenizer = "bert-base-uncased";
$secretarialNote = "filed";

// Low-signal + secret-named values, all env-sourced (not literals).
$auth = getenv("AUTH");
$token = getenv("TOKEN");
$password = getenv("PW");
$api_key = getenv("API_KEY");
$secret_key = getenv("SECRET_KEY");
