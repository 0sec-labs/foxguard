package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	mathrand "math/rand"
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

	// 9b. go/missing-ssl-minversion (Medium) — separate config so it is not
	// masked by the InsecureSkipVerify same-literal skip.
	tlsConfig := &tls.Config{ServerName: "example.com"}

	// 10. go/cookie-missing-secure (Medium)
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: userInput, HttpOnly: true})

	// 11. go/cookie-missing-httponly (Medium)
	http.SetCookie(w, &http.Cookie{Name: "prefs", Value: userInput, Secure: true})

	// 12. go/math-random-used (Medium)
	insecureCode := mathrand.Intn(1000000)

	// 13. go/no-unsafe-deserialization — gob.NewDecoder (High)
	dec := gob.NewDecoder(conn)

	// 14. go/no-unsafe-deserialization — yaml.Unmarshal into interface{} (High)
	var out interface{}
	yaml.Unmarshal(data, new(interface{}))

	// 15. go/jwt-no-verify — jwt.ParseUnverified (Critical)
	jwt.ParseUnverified(tokenStr, &jwt.StandardClaims{})

	// 16. go/jwt-no-verify — jwt.Parse with nil key function (Critical)
	jwt.Parse(tokenStr, nil)

	// 17. go/jwt-hardcoded-secret (High)
	jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) { return []byte("my-secret-key"), nil })

	_ = query1
	_ = query2
	_ = apiKey
	_ = transport
	_ = tlsConfig
	_ = insecureCode
	_ = dec
}

func getUserInput() string {
	return "malicious"
}

// go/pq-vulnerable-crypto
func pqVulnerable() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	_ = key
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = ecKey
	_, _, _ = ed25519.GenerateKey(rand.Reader)
	p256key, _ := ecdh.P256().GenerateKey(rand.Reader)
	_ = p256key
}
