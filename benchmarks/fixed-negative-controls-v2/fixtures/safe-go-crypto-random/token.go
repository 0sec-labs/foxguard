package token

import (
	"crypto/rand"
	"encoding/hex"
)

func New() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
