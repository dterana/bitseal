// ============================================================================
// Version management and file operations
// ============================================================================

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// CipherManager handles version detection and routing
type CipherManager struct {
	ciphers map[byte]CipherVersion
}

func NewCipherManager() *CipherManager {
	return &CipherManager{
		ciphers: map[byte]CipherVersion{
			1: NewCipherV1(),
			// Future versions can be added here:
			// 2: NewCipherV2(),
		},
	}
}

func (cm *CipherManager) getCipher(version byte) (CipherVersion, error) {
	cipher, ok := cm.ciphers[version]
	if !ok {
		return nil, fmt.Errorf("unsupported encryption version: %d", version)
	}
	return cipher, nil
}

// EncryptFile encrypts a file with the current cipher version
func (c *CipherV1) EncryptFile(inputPath, outputPath, password string) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	encrypted, err := c.Encrypt(plaintext, []byte(password))
	if err != nil {
		return err
	}

	if outputPath == "" {
		outputPath = inputPath + ".enc"
	}

	if err := os.WriteFile(outputPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file by detecting its version
func (cm *CipherManager) DecryptFile(inputPath, outputPath, password string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(data) < 1 {
		return fmt.Errorf("invalid encrypted file format (empty)")
	}

	version := data[0]
	cipher, err := cm.getCipher(version)
	if err != nil {
		return err
	}

	plaintext, err := cipher.Decrypt(data, []byte(password))
	if err != nil {
		return err
	}

	if outputPath == "" {
		outputPath = inputPath
		if filepath.Ext(outputPath) == ".enc" {
			outputPath = outputPath[:len(outputPath)-4]
		}
	}

	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
