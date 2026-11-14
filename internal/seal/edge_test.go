package seal

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dterana/bitseal/internal/testvectors"
)

func TestNewCipherUnknownVersion(t *testing.T) {
	if c, ok := newCipher(0, DefaultParams); ok || c != nil {
		t.Fatal("version 0 must not be constructible")
	}
	if _, ok := newCipher(255, DefaultParams); ok {
		t.Fatal("version 255 must not be constructible")
	}
}

func TestSamePathWithMissingFiles(t *testing.T) {
	dir := t.TempDir()
	exists := filepath.Join(dir, "a")
	writeFile(t, exists, []byte("x"))
	missing := filepath.Join(dir, "missing")

	if samePath(missing, exists) || samePath(exists, missing) || samePath(missing, filepath.Join(dir, "other")) {
		t.Fatal("paths that cannot be statted are not the same file")
	}
	if !samePath(exists, exists) {
		t.Fatal("a path is the same file as itself")
	}
}

// streamless hides the streaming methods of a cipher.
type streamless struct{ CipherVersion }

func TestCurrentCipherErrors(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("x"))
	enc := filepath.Join(dir, "a.enc")
	writeV1(t, enc, "x", "pw")

	t.Run("current version not wired", func(t *testing.T) {
		m := fastManager()
		delete(m.ciphers, CurrentVersion)
		for name, err := range map[string]error{
			"encrypt": m.EncryptFile(in, "", sec("pw")),
			"rekey":   m.RekeyFile(enc, "", sec("pw"), sec("pw")),
		} {
			if err == nil || !strings.Contains(err.Error(), "unsupported encryption version") {
				t.Fatalf("%s: unexpected error %v", name, err)
			}
		}
	})

	t.Run("current version cannot stream", func(t *testing.T) {
		m := fastManager()
		m.ciphers[CurrentVersion] = streamless{m.ciphers[CurrentVersion]}
		for name, err := range map[string]error{
			"encrypt": m.EncryptFile(in, "", sec("pw")),
			"rekey":   m.RekeyFile(enc, "", sec("pw"), sec("pw")),
		} {
			if err == nil || !strings.Contains(err.Error(), "does not support streaming") {
				t.Fatalf("%s: unexpected error %v", name, err)
			}
		}
	})
	noTempLeftovers(t, dir)
}

func writeV1(t *testing.T, path, content, pw string) {
	t.Helper()
	enc, err := NewCipherV1().Encrypt([]byte(content), sec(pw))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, enc)
}

func TestDecryptToStdoutWriteFailure(t *testing.T) {
	dir := t.TempDir()
	m, _ := stdioManager("")
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	m.Out = &errWriter{left: 0}
	err := m.DecryptFile(in+".enc", StdioPath, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "failed to write output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInputReadErrors(t *testing.T) {
	t.Run("before the version byte", func(t *testing.T) {
		m, _ := stdioManager("")
		m.In = &errReader{err: io.ErrClosedPipe}
		err := m.DecryptFile(StdioPath, StdioPath, sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to read file") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := m.InspectFile(StdioPath); err == nil {
			t.Fatal("inspect must fail too")
		}
	})

	t.Run("while reading a V1 file", func(t *testing.T) {
		// V1 is not streamed: the whole file is read first
		m, _ := stdioManager("")
		m.In = &errReader{data: []byte{1, 2, 3}, err: io.ErrClosedPipe}
		err := m.DecryptFile(StdioPath, StdioPath, sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to read file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("while encrypting stdin", func(t *testing.T) {
		m, out := stdioManager("")
		m.In = &errReader{data: []byte("partial"), err: io.ErrClosedPipe}
		err := m.EncryptFile(StdioPath, StdioPath, sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to read input") {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = out // ciphertext of a failed run is not a valid file; callers see the error
	})
}

// Rekey must report the encrypt-side error when decrypting already succeeded.
func TestRekeyEncryptFailsAfterDecryptSucceeded(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	f := filepath.Join(dir, "empty.enc")
	enc, _ := fastV2().Encrypt(nil, sec("pw")) // empty plaintext: nothing is piped
	writeFile(t, f, enc)

	err := m.RekeyFile(f, "", sec("pw"), Secret{})
	if err == nil || !strings.Contains(err.Error(), "password cannot be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(readFile(t, f)) != string(enc) {
		t.Fatal("file modified by a failed rekey")
	}
	noTempLeftovers(t, dir)
}

// A reader that fails exactly when the decryptor peeks for more data after a
// full chunk must surface as a read error, not as a truncated file.
func TestStreamDecryptPeekReadError(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(16), sec("pw")) // exactly one full chunk
	err := tinyV2().DecryptStream(io.Discard, &errReader{data: enc, err: io.ErrClosedPipe}, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "failed to read input") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptRefusesDirectoriesAsOutput(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	target := filepath.Join(dir, "out")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "keep"), []byte("keep"))
	enc := filepath.Join(dir, "g.enc")
	writeFile(t, enc, mustHex(t, testvectors.V2Hex))

	if err := m.DecryptFile(enc, target, sec(testvectors.Password)); err == nil {
		t.Fatal("writing onto a directory must fail")
	}
	if string(readFile(t, filepath.Join(target, "keep"))) != "keep" {
		t.Fatal("directory content damaged")
	}
	noTempLeftovers(t, dir)
}
