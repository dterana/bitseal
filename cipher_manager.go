// ============================================================================
// Version management and file operations
// ============================================================================

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// CurrentVersion is the cipher version used for new encryptions
const CurrentVersion byte = 2

// CipherManager handles version detection and routing
type CipherManager struct {
	ciphers map[byte]CipherVersion
}

func NewCipherManager() *CipherManager {
	return &CipherManager{
		ciphers: map[byte]CipherVersion{
			1: NewCipherV1(),
			2: NewCipherV2(),
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
func (cm *CipherManager) EncryptFile(inputPath, outputPath, password string) error {
	c, err := cm.getCipher(CurrentVersion)
	if err != nil {
		return err
	}

	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if outputPath == "" {
		outputPath = inputPath + ".enc"
	}
	if samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
	}

	encrypted, err := c.Encrypt(plaintext, []byte(password))
	if err != nil {
		return err
	}

	if err := writeFileAtomic(outputPath, encrypted, 0600); err != nil {
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

	if outputPath == "" {
		if filepath.Ext(inputPath) != ".enc" {
			return fmt.Errorf("cannot infer output path: input does not end in .enc, use -out")
		}
		outputPath = inputPath[:len(inputPath)-len(".enc")]
	}
	if samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
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

	if err := writeFileAtomic(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// samePath reports whether two paths refer to the same file, either by name
// or because the output already exists as the same file (e.g. a symlink).
func samePath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// writeFileAtomic writes data to a temp file in the destination directory and
// renames it into place, so a failed write never truncates an existing file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bitseal-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
