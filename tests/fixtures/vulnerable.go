package main

import (
	"crypto/tls"
	"crypto/md5"
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
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

	// 10. go/no-unsafe-deserialization (High) — gob.NewDecoder
	decoder := gob.NewDecoder(os.Stdin)

	// 11. go/no-unsafe-deserialization (High) — decoder.Decode
	var result interface{}
	decoder.Decode(&result)

	// 12. go/no-unsafe-deserialization (High) — yaml.Unmarshal into interface{}
	yaml.Unmarshal([]byte(userInput), new(interface{}))

	_ = query1
	_ = query2
	_ = apiKey
	_ = transport
	_ = result
}

func getUserInput() string {
	return "malicious"
}
