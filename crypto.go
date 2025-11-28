// ============================================================================
// Core cryptography logic
// ============================================================================

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PBKDF2Iterations = 100000
	KeySize          = 32 // 256-bit for AES-256
	NonceSize        = 12 // GCM standard
)

// CipherVersion defines the interface for different encryption versions
type CipherVersion interface {
	Version() byte
	Encrypt(plaintext, password []byte) ([]byte, error)
	Decrypt(ciphertext, password []byte) ([]byte, error)
}

// CipherV1 implements AES-256-GCM with PBKDF2
type CipherV1 struct {
	version byte
	salt    string
}

func NewCipherV1() *CipherV1 {
	return &CipherV1{
		version: 1,
		salt:    "static-salt-v1",
	}
}

func (c *CipherV1) Version() byte {
	return c.version
}

func (c *CipherV1) deriveKey(password []byte) []byte {
	return pbkdf2.Key(
		password,
		[]byte(c.salt),
		PBKDF2Iterations,
		KeySize,
		sha256.New,
	)
}

func (c *CipherV1) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	key := c.deriveKey(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Format: [version:1][nonce:12][ciphertext]
	output := bytes.NewBuffer(nil)
	output.WriteByte(c.version)
	output.Write(nonce)
	output.Write(ciphertext)

	return output.Bytes(), nil
}

func (c *CipherV1) Decrypt(ciphertext, password []byte) ([]byte, error) {
	if len(ciphertext) < 29 { // 1 (version) + 12 (nonce) + 16 (min GCM tag)
		return nil, fmt.Errorf("invalid encrypted file format (too short)")
	}

	key := c.deriveKey(password)

	nonce := ciphertext[1:13]
	encrypted := ciphertext[13:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or corrupted file): %w", err)
	}

	return plaintext, nil
}
