package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
)

func safeOperations(db *sql.DB) {
	// Safe: parameterized query
	db.Query("SELECT * FROM users WHERE id = ?", 1)

	// Safe: static command
	exec.Command("ls", "-la")

	// Safe: strong crypto
	h := sha256.New()
	h.Write([]byte("data"))

	// Safe: static URL
	http.Get("https://api.example.com/health")
	http.NewRequest("GET", "https://api.example.com/health", nil)

	// Safe: dynamic URL targeting an httptest server is not an SSRF sink.
	ts := httptest.NewServer(nil)
	defer ts.Close()
	http.Get(ts.URL + "/x")

	// Safe: TLS verification remains enabled
	_ = &tls.Config{MinVersion: tls.VersionTLS12}

	// Safe: cookie has transport and script protections enabled
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Secure: true, HttpOnly: true})

	// Safe: cryptographic randomness
	token := make([]byte, 16)
	rand.Read(token)
	_ = token

	// Safe: environment variable for secrets
	fmt.Println("Application started")
}
