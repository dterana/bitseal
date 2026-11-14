// ============================================================================
// Version management and file operations
// ============================================================================

package seal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

// CurrentVersion is the cipher version used for new encryptions. Raising it
// is the single switch that makes a newly registered version the default.
const CurrentVersion byte = 2

// StdioPath selects stdin as input or stdout as output.
const StdioPath = "-"

// Manager routes files to the cipher version named in their header and
// implements the file operations on top of the ciphers.
type Manager struct {
	ciphers map[byte]CipherVersion

	// In, Out and OutIsTerminal serve the "-" paths. NewManager wires them to
	// the process streams; callers (and tests) may replace them.
	In            io.Reader
	Out           io.Writer
	OutIsTerminal func() bool
}

// NewManager returns a manager with the default parameters.
func NewManager() *Manager {
	return NewManagerWith(DefaultParams.KDF, DefaultParams.ChunkLog2)
}

// NewManagerWith lets callers choose the KDF cost and chunk size used when
// encrypting. Decryption always follows the parameters stored in each file.
func NewManagerWith(kdf KDFParams, chunkLog2 uint8) *Manager {
	p := Params{KDF: kdf, ChunkLog2: chunkLog2}
	m := &Manager{
		ciphers: map[byte]CipherVersion{},
		In:      os.Stdin,
		Out:     os.Stdout,
		OutIsTerminal: func() bool {
			return term.IsTerminal(int(os.Stdout.Fd()))
		},
	}
	for _, v := range Versions() {
		c, _ := newCipher(v, p)
		m.ciphers[v] = c
	}
	return m
}

func (m *Manager) getCipher(version byte) (CipherVersion, error) {
	cipher, ok := m.ciphers[version]
	if !ok {
		return nil, fmt.Errorf("unsupported encryption version: %d", version)
	}
	return cipher, nil
}

func (m *Manager) currentCipher() (StreamCipher, error) {
	c, err := m.getCipher(CurrentVersion)
	if err != nil {
		return nil, err
	}
	sc, ok := c.(StreamCipher)
	if !ok {
		return nil, fmt.Errorf("cipher version %d does not support streaming", CurrentVersion)
	}
	return sc, nil
}

// ResolveEncryptOut picks the default output for encrypt.
func ResolveEncryptOut(in, out string) string {
	switch {
	case out != "":
		return out
	case in == StdioPath:
		return StdioPath
	}
	return in + ".enc"
}

// ResolveDecryptOut picks the default output for decrypt.
func ResolveDecryptOut(in, out string) (string, error) {
	switch {
	case out != "":
		return out, nil
	case in == StdioPath:
		return StdioPath, nil
	case filepath.Ext(in) != ".enc":
		return "", fmt.Errorf("cannot infer output path: input does not end in .enc, use -out")
	}
	return in[:len(in)-len(".enc")], nil
}

func (m *Manager) openInput(path string) (io.Reader, func(), error) {
	if path == StdioPath {
		return m.In, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	fi, err := f.Stat()
	if err == nil && fi.IsDir() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("failed to read file: %s is a directory (archive it first, e.g. with tar)", path)
	}
	return f, func() { _ = f.Close() }, nil
}

// writeOutput runs fn against the destination. Files are written atomically.
// For stdout, buffered holds the output back until fn succeeded, so
// unauthenticated plaintext never reaches a pipe.
func (m *Manager) writeOutput(out string, buffered bool, fn func(io.Writer) error) error {
	if out != StdioPath {
		return writeAtomicWith(out, 0600, fn)
	}
	if !buffered {
		return fn(m.Out)
	}
	var buf bytes.Buffer
	defer func() { Wipe(buf.Bytes()) }()
	if err := fn(&buf); err != nil {
		return err
	}
	if _, err := m.Out.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

// EncryptFile encrypts a file (or stdin) with the current cipher version
func (m *Manager) EncryptFile(inputPath, outputPath string, secret Secret) error {
	sc, err := m.currentCipher()
	if err != nil {
		return err
	}

	src, closeSrc, err := m.openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	outputPath = ResolveEncryptOut(inputPath, outputPath)
	if inputPath != StdioPath && outputPath != StdioPath && samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
	}
	if outputPath == StdioPath && m.OutIsTerminal() {
		return fmt.Errorf("refusing to write encrypted data to a terminal; use -out <file> or redirect stdout")
	}

	return m.writeOutput(outputPath, false, func(w io.Writer) error {
		return sc.EncryptStream(w, src, secret)
	})
}

// openCipher peeks the version byte of src and returns the matching cipher
// together with a reader that still includes that byte.
func (m *Manager) openCipher(src io.Reader) (CipherVersion, *bufio.Reader, error) {
	br := bufio.NewReader(src)
	first, err := br.Peek(1)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, fmt.Errorf("invalid encrypted file format (empty)")
		}
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	c, err := m.getCipher(first[0])
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
	defer Wipe(plaintext)
	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}
	return nil
}

// DecryptFile decrypts a file (or stdin) by detecting its version
func (m *Manager) DecryptFile(inputPath, outputPath string, secret Secret) error {
	src, closeSrc, err := m.openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	outputPath, err = ResolveDecryptOut(inputPath, outputPath)
	if err != nil {
		return err
	}
	if inputPath != StdioPath && outputPath != StdioPath && samePath(inputPath, outputPath) {
		return fmt.Errorf("output path must differ from input path")
	}

	c, br, err := m.openCipher(src)
	if err != nil {
		return err
	}

	return m.writeOutput(outputPath, true, func(w io.Writer) error {
		return decryptTo(c, w, br, secret)
	})
}

// RekeyFile decrypts a file with oldSecret and re-encrypts it with the
// current format and newSecret. With outputPath empty the file is replaced
// in place (atomically). Plaintext is piped between the two steps and never
// touches the disk.
func (m *Manager) RekeyFile(inputPath, outputPath string, oldSecret, newSecret Secret) error {
	if inputPath == StdioPath || outputPath == StdioPath {
		return fmt.Errorf("rekey works on files only, not stdin or stdout")
	}
	sc, err := m.currentCipher()
	if err != nil {
		return err
	}

	src, closeSrc, err := m.openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	if outputPath == "" {
		outputPath = inputPath
	}

	oldCipher, br, err := m.openCipher(src)
	if err != nil {
		return err
	}

	return m.writeOutput(outputPath, false, func(w io.Writer) error {
		pr, pw := io.Pipe()
		decErrc := make(chan error, 1)
		go func() {
			err := decryptTo(oldCipher, pw, br, oldSecret)
			_ = pw.CloseWithError(err)
			decErrc <- err
		}()

		encErr := sc.EncryptStream(w, pr, newSecret)
		_ = pr.CloseWithError(encErr)
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
func (m *Manager) InspectFile(inputPath string) (FileInfo, error) {
	src, closeSrc, err := m.openInput(inputPath)
	if err != nil {
		return FileInfo{}, err
	}
	defer closeSrc()

	c, br, err := m.openCipher(src)
	if err != nil {
		return FileInfo{}, err
	}
	return c.Inspect(br)
}
