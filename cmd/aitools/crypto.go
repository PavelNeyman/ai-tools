package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const cryptoMagic = "AITOOLS1"

func deriveKey(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

// encryptBytes AES-256-GCM; output is base64(magic|nonce|ciphertext).
func encryptBytes(plain []byte, passphrase string) (string, error) {
	if strings.TrimSpace(passphrase) == "" {
		return "", fmt.Errorf("empty passphrase")
	}
	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	raw := append(append([]byte(cryptoMagic), nonce...), ct...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

func decryptBytes(encoded, passphrase string) ([]byte, error) {
	if strings.TrimSpace(passphrase) == "" {
		return nil, fmt.Errorf("empty passphrase")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	if len(raw) < len(cryptoMagic)+12 {
		return nil, fmt.Errorf("ciphertext too short")
	}
	if string(raw[:len(cryptoMagic)]) != cryptoMagic {
		return nil, fmt.Errorf("not an aitools ciphertext (missing magic); old base64-only files are not supported")
	}
	raw = raw[len(cryptoMagic):]
	block, err := aes.NewCipher(deriveKey(passphrase))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext truncated")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

func cryptoPassphrase() string {
	if len(os.Args) >= 4 && strings.TrimSpace(os.Args[3]) != "" {
		return os.Args[3]
	}
	if k := strings.TrimSpace(os.Getenv("AITOOLS_KEY")); k != "" {
		return k
	}
	return ""
}
