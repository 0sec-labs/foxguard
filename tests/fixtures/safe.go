package main

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func safeOperations(db *sql.DB) {
	// Safe: parameterized query
	db.Query("SELECT * FROM users WHERE id = ?", 1)

	// Safe: static command
	exec.Command("ls", "-la")

	// Safe: crypto usage via abstraction (no direct crypto/* import)
	hash := computeHash([]byte("data"))

	// Safe: static URL
	http.Get("https://api.example.com/health")
	http.NewRequest("GET", "https://api.example.com/health", nil)

	// Safe: TLS verification remains enabled
	_ = &tls.Config{MinVersion: tls.VersionTLS12}

	// Safe: environment variable for secrets
	fmt.Println("Application started")
}
