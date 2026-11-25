package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const encPrefix = "enc:v1:"

// Box optionally encrypts and decrypts secret strings at rest using AES-256-GCM.
// When key is empty, Seal and Open pass plaintext through unchanged.
type Box struct {
	gcm cipher.AEAD
}

// NewBox creates a Box from a 32-byte AES key, or a passthrough Box if key is empty.
func NewBox(key []byte) (*Box, error) {
	if len(key) == 0 {
		return &Box{}, nil
	}
	if len(key) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &Box{gcm: gcm}, nil
}

// Enabled reports whether at-rest encryption is active.
func (b *Box) Enabled() bool {
	return b != nil && b.gcm != nil
}

// Seal encrypts plaintext if a master key is configured. Empty strings remain empty.
func (b *Box) Seal(plaintext string) (string, error) {
	if plaintext == "" || !b.Enabled() {
		return plaintext, nil
	}
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	sealed := b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a sealed value, or returns plaintext values as-is when unprefixed.
func (b *Box) Open(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, encPrefix) {
		return stored, nil
	}
	if !b.Enabled() {
		return "", errors.New("encrypted secret encountered but OBSERVER_MASTER_KEY is not set")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil {
		return "", fmt.Errorf("decode encrypted secret: %w", err)
	}
	nonceSize := b.gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("encrypted secret truncated")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := b.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plain), nil
}
