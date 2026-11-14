// ============================================================================
// Version management and file operations
// ============================================================================

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// CurrentVersion is the cipher version used for new encryptions
const CurrentVersion byte = 2

// stdioPath selects stdin as input or stdout as output.
const stdioPath = "-"

// CipherManager handles version detection and routing
type CipherManager struct {
	ciphers map[byte]CipherVersion
}

func NewCipherManager() *CipherManager {
	return newCipherManagerWith(defaultKDF, defaultChunkLog2)
}

// newCipherManagerWith lets tests use cheap KDF parameters and tiny chunks.
func newCipherManagerWith(kdf kdfParams, chunkLog2 uint8) *CipherManager {
	return &CipherManager{
		ciphers: map[byte]CipherVersion{
			1: NewCipherV1(),
			2: newCipherV2With(kdf, chunkLog2),
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

func (cm *CipherManager) currentCipher() (StreamCipher, error) {
	c, err := cm.getCipher(CurrentVersion)
	if err != nil {
		return nil, err
	}
	sc, ok := c.(StreamCipher)
	if !ok {
		return nil, fmt.Errorf("cipher version %d does not support streaming", CurrentVersion)
	}
	return sc, nil
}

// resolveEncryptOut picks the default output for encrypt.
func resolveEncryptOut(in, out string) string {
	switch {
	case out != "":
		return out
	case in == stdioPath:
		return stdioPath
	}
	return in + ".enc"
}

// resolveDecryptOut picks the default output for decrypt.
func resolveDecryptOut(in, out string) (string, error) {
	switch {
	case out != "":
		return out, nil
	case in == stdioPath:
		return stdioPath, nil
	case filepath.Ext(in) != ".enc":
		return "", fmt.Errorf("cannot infer output path: input does not end in .enc, use -out")
	}
	return in[:len(in)-len(".enc")], nil
}

func openInput(path string) (io.Reader, func(), error) {
	if path == stdioPath {
		return stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	fi, err := f.Stat()
	if err == nil && fi.IsDir() {
		f.Close()
		return nil, nil, fmt.Errorf("failed to read file: %s is a directory (archive it first, e.g. with tar)", path)
	}
	return f, func() { f.Close() }, nil
}

// writeOutput runs fn against the destination. Files are written atomically.
// For stdout, buffered holds the output back until fn succeeded, so
// unauthenticated plaintext never reaches a pipe.
func writeOutput(out string, buffered bool, fn func(io.Writer) error) error {
	if out != stdioPath {
		return writeAtomicWith(out, 0600, fn)
	}
	if !buffered {
		return fn(stdout)
	}
	var buf bytes.Buffer
	defer func() { wipe(buf.Bytes()) }()
	if err := fn(&buf); err != nil {
		return err
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

// EncryptFile encrypts a file (or stdin) with the current cipher version
func (cm *CipherManager) EncryptFile(inputPath, outputPath string, secret Secret) error {
	sc, err := cm.currentCipher()
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	outputPath = resolveEncryptOut(inputPath, outputPath)
	if inputPath != stdioPath && outputPath != stdioPath && samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
	}
	if outputPath == stdioPath && stdoutIsTerminal() {
		return fmt.Errorf("refusing to write encrypted data to a terminal; use -out <file> or redirect stdout")
	}

	return writeOutput(outputPath, false, func(w io.Writer) error {
		return sc.EncryptStream(w, src, secret)
	})
}

// openCipher peeks the version byte of src and returns the matching cipher
// together with a reader that still includes that byte.
func (cm *CipherManager) openCipher(src io.Reader) (CipherVersion, *bufio.Reader, error) {
	br := bufio.NewReader(src)
	first, err := br.Peek(1)
	if err != nil {
		if err == io.EOF {
			return nil, nil, fmt.Errorf("invalid encrypted file format (empty)")
		}
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	c, err := cm.getCipher(first[0])
	if err != nil {
		return nil, nil, err
	}
	return c, br, nil
}

// decryptTo decrypts src into w, streaming when the cipher supports it.
func decryptTo(c CipherVersion, w io.Writer, src io.Reader, secret Secret) error {
	if sc, ok := c.(StreamCipher); ok {
		return sc.DecryptStream(w, src, secret)
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	plaintext, err := c.Decrypt(data, secret)
	if err != nil {
		return err
	}
	defer wipe(plaintext)
	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

// DecryptFile decrypts a file (or stdin) by detecting its version
func (cm *CipherManager) DecryptFile(inputPath, outputPath string, secret Secret) error {
	src, closeSrc, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	outputPath, err = resolveDecryptOut(inputPath, outputPath)
	if err != nil {
		return err
	}
	if inputPath != stdioPath && outputPath != stdioPath && samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
	}

	c, br, err := cm.openCipher(src)
	if err != nil {
		return err
	}

	return writeOutput(outputPath, true, func(w io.Writer) error {
		return decryptTo(c, w, br, secret)
	})
}

// RekeyFile decrypts a file with oldSecret and re-encrypts it with the
// current format and newSecret. With outputPath empty the file is replaced
// in place (atomically). Plaintext is piped between the two steps and never
// touches the disk.
func (cm *CipherManager) RekeyFile(inputPath, outputPath string, oldSecret, newSecret Secret) error {
	if inputPath == stdioPath || outputPath == stdioPath {
		return fmt.Errorf("rekey works on files only, not stdin or stdout")
	}
	sc, err := cm.currentCipher()
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	if outputPath == "" {
		outputPath = inputPath
	}

	oldCipher, br, err := cm.openCipher(src)
	if err != nil {
		return err
	}

	return writeOutput(outputPath, false, func(w io.Writer) error {
		pr, pw := io.Pipe()
		decErrc := make(chan error, 1)
		go func() {
			err := decryptTo(oldCipher, pw, br, oldSecret)
			pw.CloseWithError(err)
			decErrc <- err
		}()

		encErr := sc.EncryptStream(w, pr, newSecret)
		pr.CloseWithError(encErr)
		decErr := <-decErrc

		switch {
		case encErr == nil:
			return decErr
		case decErr == nil:
			return encErr
		case errors.Is(encErr, decErr):
			return decErr // the encrypt side only reported the decrypt failure
		default:
			return encErr
		}
	})
}

// InspectFile describes a file's format without decrypting it.
func (cm *CipherManager) InspectFile(inputPath string) (FileInfo, error) {
	src, closeSrc, err := openInput(inputPath)
	if err != nil {
		return FileInfo{}, err
	}
	defer closeSrc()

	c, br, err := cm.openCipher(src)
	if err != nil {
		return FileInfo{}, err
	}
	return c.Inspect(br)
}
