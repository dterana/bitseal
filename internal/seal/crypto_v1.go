// ============================================================================
// CipherV1: legacy single-block AES-256-GCM with PBKDF2 and a static salt
// ============================================================================
//
// Format: [version=1:1][nonce:12][ciphertext + tag]. Kept so old files keep
// decrypting; new files are written with the current version.

package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const PBKDF2Iterations = 100000

func init() {
	register(1, func(Params) CipherVersion { return NewCipherV1() })
}

// CipherV1 implements AES-256-GCM with PBKDF2 and a static salt (legacy,
// decrypt only in practice).
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

func (c *CipherV1) Encrypt(plaintext []byte, secret Secret) ([]byte, error) {
	if len(secret.Password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if secret.hasKeyFile() {
		return nil, fmt.Errorf("key files require encryption version 2")
	}

	key := c.deriveKey(secret.Password)
	defer Wipe(key)

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

func (c *CipherV1) Decrypt(ciphertext []byte, secret Secret) ([]byte, error) {
	if len(ciphertext) < 1+NonceSize+gcmTagSize {
		return nil, fmt.Errorf("invalid encrypted file format (too short)")
	}
	if secret.hasKeyFile() {
		return nil, fmt.Errorf("this file was not encrypted with a key file")
	}

	key := c.deriveKey(secret.Password)
	defer Wipe(key)

	nonce := ciphertext[1 : 1+NonceSize]
	encrypted := ciphertext[1+NonceSize:]

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

func (c *CipherV1) Inspect(src io.Reader) (FileInfo, error) {
	header := make([]byte, 1+NonceSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return FileInfo{}, fmt.Errorf("invalid encrypted file format (too short)")
	}
	if header[0] != c.version {
		return FileInfo{}, fmt.Errorf("not a version 1 file")
	}
	return FileInfo{
		Version: c.version,
		Cipher:  "AES-256-GCM (single block)",
		KDF:     fmt.Sprintf("PBKDF2-HMAC-SHA256, %d iterations, static salt", PBKDF2Iterations),
		Legacy:  true,
	}, nil
}
