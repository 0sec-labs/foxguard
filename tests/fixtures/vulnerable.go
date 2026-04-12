package main

import (
	"crypto/tls"
	"crypto/md5"
	"fmt"
	"net/http"
	"os/exec"
)

func vulnerable() {
	userInput := getUserInput()

	// 1. go/no-sql-injection — string concat (Critical)
	query1 := "SELECT * FROM users WHERE id = " + userInput

	// 2. go/no-sql-injection — fmt.Sprintf (Critical)
	query2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)

	// 3. go/no-command-injection (Critical)
	exec.Command(userInput)

	// 4. go/no-hardcoded-secret (High)
	apiKey := "sk-live-abcdef123456789"

	// 5. go/no-weak-crypto (Medium) — import already triggers, plus usage:
	md5.New()

	// 6. go/no-ssrf (High)
	http.Get(userInput)

	// 7. go/no-ssrf (High) via NewRequest
	http.NewRequest("GET", userInput, nil)

	// 8. go/net-http-no-timeout (Medium)
	http.ListenAndServe(":8080", nil)

	// 9. go/insecure-tls-skip-verify (High)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 10. go/no-unsafe-deserialization — gob.NewDecoder (High)
	dec := gob.NewDecoder(conn)

	// 11. go/no-unsafe-deserialization — yaml.Unmarshal into interface{} (High)
	var out interface{}
	yaml.Unmarshal(data, new(interface{}))

	// 12. go/jwt-no-verify — jwt.ParseUnverified (Critical)
	jwt.ParseUnverified(tokenStr, &jwt.StandardClaims{})

	// 13. go/jwt-no-verify — jwt.Parse with nil key function (Critical)
	jwt.Parse(tokenStr, nil)

	// 14. go/jwt-hardcoded-secret (High)
	jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return []byte("my-secret-key"), nil })

	_ = query1
	_ = query2
	_ = apiKey
	_ = transport
	_ = dec
}

func getUserInput() string {
	return "malicious"
}
