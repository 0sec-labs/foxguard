package main

import "os"

// Benign names containing secret-keyword substrings, or low-signal
// keywords with non-secret values. None should be flagged by
// go/no-hardcoded-secret after the word-boundary + value-gate fix.

func config() {
	// Substring false positives.
	author := "Pallets"
	authors := "core team"
	authenticated := "yes"
	authorization := "X-Custom"
	tokenizer := "bert-base-uncased"
	secretarial := "filed"

	// Low-signal + secret-named values, all env-sourced (not literals).
	auth := os.Getenv("AUTH")
	token := os.Getenv("TOKEN")
	password := os.Getenv("PW")
	apiKey := os.Getenv("API_KEY")
	secretKey := os.Getenv("SECRET_KEY")

	_ = author
	_ = authors
	_ = authenticated
	_ = authorization
	_ = tokenizer
	_ = secretarial
	_ = auth
	_ = token
	_ = password
	_ = apiKey
	_ = secretKey
}
