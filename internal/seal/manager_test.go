package seal

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dterana/casemate/internal/testvectors"
)

func TestManagerRegistersAllVersions(t *testing.T) {
	m := NewManager()
	for _, v := range []byte{1, 2} {
		c, err := m.getCipher(v)
		if err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if c.Version() != v {
			t.Fatalf("version %d mapped to cipher %d", v, c.Version())
		}
	}
	if _, err := m.currentCipher(); err != nil {
		t.Fatalf("CurrentVersion not usable for streaming: %v", err)
	}
}

func TestManagerUnsupportedVersions(t *testing.T) {
	m := NewManager()
	for _, v := range []byte{0, 3, 99, 255} {
		if _, err := m.getCipher(v); err == nil {
			t.Fatalf("version %d should be unsupported", v)
		}
	}
}

func TestDefaultManagerUsesDefaultParameters(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := NewManager().EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	h, err := parseHeaderV2(readFile(t, in+".enc"))
	if err != nil {
		t.Fatal(err)
	}
	if h.kdf != DefaultKDF || h.chunkLog2 != DefaultChunkLog2 {
		t.Fatalf("default manager wrote %+v / %d", h.kdf, h.chunkLog2)
	}
}

func TestEncryptFileDefaultsToCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := fastManager().EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, in+".enc")[0]; got != CurrentVersion {
		t.Fatalf("version = %d, want %d", got, CurrentVersion)
	}
}

func TestEncryptFileKeepsInput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := fastManager().EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, in), []byte("hello")) {
		t.Fatal("input file must be left untouched")
	}
}

func TestEncryptFileCustomOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	out := filepath.Join(dir, "custom.bin")
	writeFile(t, in, []byte("hello"))
	if err := fastManager().EncryptFile(in, out, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("custom output not written")
	}
	if _, err := os.Stat(in + ".enc"); err == nil {
		t.Fatal("default .enc output must not be written when -out is given")
	}
}

func TestOutputFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	m := fastManager()
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "out.txt"), sec("pw")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{in + ".enc", filepath.Join(dir, "out.txt")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %v, want 0600", p, fi.Mode().Perm())
		}
	}
}

func TestEncryptFileOverwritesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("new"))
	writeFile(t, in+".enc", []byte("stale"))
	m := fastManager()
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o")
	if err := m.DecryptFile(in+".enc", out, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, out)) != "new" {
		t.Fatal("stale output was not replaced")
	}
}

func TestEncryptFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	t.Run("missing input", func(t *testing.T) {
		err := m.EncryptFile(filepath.Join(dir, "nope"), "", sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to read file") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("empty password", func(t *testing.T) {
		in := filepath.Join(dir, "a.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, "", Secret{}); err == nil {
			t.Fatal("expected error")
		}
		if _, err := os.Stat(in + ".enc"); err == nil {
			t.Fatal("no output may be written when encryption fails")
		}
	})
	t.Run("unwritable output dir", func(t *testing.T) {
		in := filepath.Join(dir, "b.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, filepath.Join(dir, "missing", "out.enc"), sec("pw")); err == nil {
			t.Fatal("expected error")
		}
	})
	noTempLeftovers(t, dir)
}

func TestDecryptFileDefaultOutputStripsEnc(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "notes.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	os.Remove(in)
	if err := m.DecryptFile(in+".enc", "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("default decrypt output should be the name without .enc")
	}
}

func TestDecryptFileNonEncExtensionRequiresOut(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	enc, _ := fastV2().Encrypt([]byte("hello"), sec("pw"))
	in := filepath.Join(dir, "blob.bin")
	writeFile(t, in, enc)

	err := m.DecryptFile(in, "", sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "use -out") {
		t.Fatalf("expected inference error, got %v", err)
	}
	if !bytes.Equal(readFile(t, in), enc) {
		t.Fatal("encrypted input must be left untouched")
	}

	out := filepath.Join(dir, "blob.txt")
	if err := m.DecryptFile(in, out, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, out)) != "hello" {
		t.Fatal("explicit -out should work")
	}
}

func TestOutputMustDifferFromInput(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))

	if err := m.EncryptFile(in, in, sec("pw")); err == nil {
		t.Fatal("encrypt must refuse output == input")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("input was clobbered")
	}
	if err := m.EncryptFile(in, filepath.Join(dir, ".", "a.txt"), sec("pw")); err == nil {
		t.Fatal("encrypt must refuse equivalent paths")
	}

	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	enc := readFile(t, in+".enc")
	if err := m.DecryptFile(in+".enc", in+".enc", sec("pw")); err == nil {
		t.Fatal("decrypt must refuse output == input")
	}
	if !bytes.Equal(readFile(t, in+".enc"), enc) {
		t.Fatal("encrypted input was clobbered")
	}
}

func TestOutputMustDifferFromInputViaSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	link := filepath.Join(dir, "link.txt")
	writeFile(t, in, []byte("hello"))
	if err := os.Symlink(in, link); err != nil {
		t.Skip("symlink unsupported")
	}
	if err := fastManager().EncryptFile(in, link, sec("pw")); err == nil {
		t.Fatal("encrypt must refuse a symlink to the input as output")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("input was clobbered")
	}
}

func TestDecryptFileWrongPasswordLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", sec("right")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	if err := m.DecryptFile(in+".enc", out, sec("wrong")); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("no plaintext output may exist after a failed decrypt")
	}
	noTempLeftovers(t, dir)
}

func TestDecryptFileWrongPasswordKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", sec("right")); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", "", sec("wrong")); err == nil {
		t.Fatal("expected failure")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("existing file was clobbered by a failed decrypt")
	}
}

// A file corrupted deep inside must not leave a partial plaintext behind,
// even though earlier chunks decrypted fine.
func TestDecryptFileCorruptLaterChunkLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerWith(fastKDF, tinyChunk)
	in := filepath.Join(dir, "a.bin")
	writeFile(t, in, pattern(500))
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	enc := readFile(t, in+".enc")
	enc[len(enc)-20] ^= 0x01
	writeFile(t, in+".enc", enc)

	out := filepath.Join(dir, "out.bin")
	if err := m.DecryptFile(in+".enc", out, sec("pw")); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("partial plaintext left behind")
	}
	noTempLeftovers(t, dir)
}

func TestDecryptFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	out := filepath.Join(dir, "out")

	cases := map[string][]byte{
		"empty file":          {},
		"unknown version 0":   append([]byte{0}, make([]byte, 64)...),
		"unknown version 3":   append([]byte{3}, make([]byte, 64)...),
		"unknown version 255": append([]byte{255}, make([]byte, 64)...),
		"plain text file":     []byte("this is not an encrypted file at all, really"),
		"version only v1":     {1},
		"version only v2":     {2},
		"v2 header only":      fastV2().headerOnlyForTest(),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			in := filepath.Join(dir, "in.enc")
			writeFile(t, in, data)
			if err := m.DecryptFile(in, out, sec("pw")); err == nil {
				t.Fatal("expected error")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("no output may be written on failure")
			}
		})
	}

	t.Run("missing input", func(t *testing.T) {
		if err := m.DecryptFile(filepath.Join(dir, "nope.enc"), out, sec("pw")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("input is a directory", func(t *testing.T) {
		if err := m.DecryptFile(dir, out, sec("pw")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unwritable output dir", func(t *testing.T) {
		in := filepath.Join(dir, "ok.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, "", sec("pw")); err != nil {
			t.Fatal(err)
		}
		if err := m.DecryptFile(in+".enc", filepath.Join(dir, "missing", "o"), sec("pw")); err == nil {
			t.Fatal("expected error")
		}
	})
	noTempLeftovers(t, dir)
}

// headerOnlyForTest returns a valid V2 header with no chunks.
func (c *CipherV2) headerOnlyForTest() []byte {
	enc, _ := c.Encrypt(nil, sec("pw"))
	return enc[:headerSizeV2]
}

func TestUnsupportedVersionErrorMessage(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.enc")
	writeFile(t, in, append([]byte{42}, make([]byte, 64)...))
	err := fastManager().DecryptFile(in, filepath.Join(dir, "o"), sec("pw"))
	if err == nil || err.Error() != "unsupported encryption version: 42" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptFileRoutesByVersionByte(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, err := c.Encrypt([]byte("routed"), sec("pw"))
			if err != nil {
				t.Fatal(err)
			}
			in := filepath.Join(dir, name+".enc")
			out := filepath.Join(dir, name+".txt")
			writeFile(t, in, enc)
			if err := m.DecryptFile(in, out, sec("pw")); err != nil {
				t.Fatal(err)
			}
			if string(readFile(t, out)) != "routed" {
				t.Fatal("wrong plaintext")
			}
		})
	}
}

func TestFileRoundTripEdgeCases(t *testing.T) {
	m := NewManagerWith(fastKDF, 8)
	cases := map[string][]byte{
		"empty":        {},
		"binary":       {0x00, 0xff, 0x10, 0x80},
		"one chunk":    pattern(256),
		"chunk + 1":    pattern(257),
		"many chunks":  pattern(256*50 + 3),
		"exact chunks": pattern(256 * 4),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "f")
			writeFile(t, in, content)
			if err := m.EncryptFile(in, "", sec("pw")); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "g")
			if err := m.DecryptFile(in+".enc", out, sec("pw")); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readFile(t, out), content) {
				t.Fatal("content mismatch")
			}
		})
	}
}

func TestLargeFileRoundTripDefaultChunk(t *testing.T) {
	if testing.Short() {
		t.Skip("large file skipped in short mode")
	}
	m := NewManagerWith(fastKDF, DefaultChunkLog2)
	dir := t.TempDir()
	in := filepath.Join(dir, "big")
	content := pattern(3<<20 + 123)
	writeFile(t, in, content)
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "big.out")
	if err := m.DecryptFile(in+".enc", out, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, out), content) {
		t.Fatal("content mismatch")
	}
}

func TestFilenamesWithSpacesAndUnicode(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "my secret é日本.txt")
	writeFile(t, in, []byte("hi"))
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	os.Remove(in)
	if err := m.DecryptFile(in+".enc", "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, in)) != "hi" {
		t.Fatal("mismatch")
	}
}

func TestKeyFileFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", secKF("pw", "kf")); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "x"), sec("pw")); err == nil {
		t.Fatal("decrypt without the key file must fail")
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "y"), secKF("pw", "kf")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, filepath.Join(dir, "y"))) != "hello" {
		t.Fatal("mismatch")
	}
	noTempLeftovers(t, dir)
}

// ----------------------------------------------------------------------------
// stdin / stdout
// ----------------------------------------------------------------------------

func TestEncryptStdinToFileAndBack(t *testing.T) {
	dir := t.TempDir()
	m, out := stdioManager("from stdin")
	enc := filepath.Join(dir, "s.enc")
	if err := m.EncryptFile(StdioPath, enc, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("nothing may be written to stdout when -out is a file")
	}
	plain := filepath.Join(dir, "s.txt")
	if err := m.DecryptFile(enc, plain, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, plain)) != "from stdin" {
		t.Fatal("mismatch")
	}
}

func TestEncryptStdinDefaultsToStdout(t *testing.T) {
	m, out := stdioManager("payload")
	if err := m.EncryptFile(StdioPath, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dec, err := fastV2().Decrypt(out.Bytes(), sec("pw"))
	if err != nil || string(dec) != "payload" {
		t.Fatalf("stdout does not hold a valid encrypted file: %v", err)
	}
}

func TestEncryptToTerminalRefused(t *testing.T) {
	dir := t.TempDir()
	m, out := stdioManager("")
	m.OutIsTerminal = func() bool { return true }
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("x"))
	err := m.EncryptFile(in, StdioPath, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("unexpected: %v", err)
	}
	if out.Len() != 0 {
		t.Fatal("binary data written to a terminal")
	}
}

func TestDecryptToStdout(t *testing.T) {
	dir := t.TempDir()
	m, out := stdioManager("")
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("secret value"))
	if err := m.EncryptFile(in, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", StdioPath, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "secret value" {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestDecryptStdinDefaultsToStdout(t *testing.T) {
	enc, _ := fastV2().Encrypt([]byte("via pipe"), sec("pw"))
	m, out := stdioManager(string(enc))
	if err := m.DecryptFile(StdioPath, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "via pipe" {
		t.Fatalf("stdout = %q", out.String())
	}
}

// Plaintext must reach stdout only after the whole file authenticated.
func TestDecryptToStdoutIsAllOrNothing(t *testing.T) {
	enc, _ := newCipherV2With(fastKDF, tinyChunk).Encrypt(pattern(500), sec("pw"))
	enc[len(enc)-20] ^= 0x01 // corrupt a late chunk
	m, out := stdioManager(string(enc))
	if err := m.DecryptFile(StdioPath, StdioPath, sec("pw")); err == nil {
		t.Fatal("expected failure")
	}
	if out.Len() != 0 {
		t.Fatalf("%d plaintext bytes reached stdout before authentication finished", out.Len())
	}
}

func TestDecryptV1ToStdout(t *testing.T) {
	m, out := stdioManager(string(mustHex(t, testvectors.V1Hex)))
	if err := m.DecryptFile(StdioPath, "", sec(testvectors.Password)); err != nil {
		t.Fatal(err)
	}
	if out.String() != testvectors.Plaintext {
		t.Fatalf("stdout = %q", out.String())
	}
}

// ----------------------------------------------------------------------------
// Rekey
// ----------------------------------------------------------------------------

func writeV1File(t *testing.T, path, content, pw string) {
	t.Helper()
	enc, err := NewCipherV1().Encrypt([]byte(content), sec(pw))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, enc)
}

func decryptedContent(t *testing.T, m *Manager, path string, s Secret) (string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "plain")
	if err := m.DecryptFile(path, out, s); err != nil {
		return "", err
	}
	return string(readFile(t, out)), nil
}

func TestRekeyUpgradesV1InPlace(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	f := filepath.Join(dir, "legacy.enc")
	writeV1File(t, f, "legacy secret", "pw")

	if err := m.RekeyFile(f, "", sec("pw"), sec("pw")); err != nil {
		t.Fatal(err)
	}
	if readFile(t, f)[0] != 2 {
		t.Fatal("file should now be V2")
	}
	got, err := decryptedContent(t, m, f, sec("pw"))
	if err != nil || got != "legacy secret" {
		t.Fatalf("content = %q, %v", got, err)
	}
	noTempLeftovers(t, dir)
}

func TestRekeyV2GetsFreshSalt(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	f := filepath.Join(dir, "a.enc")
	enc, _ := fastV2().Encrypt([]byte("x"), sec("pw"))
	writeFile(t, f, enc)

	if err := m.RekeyFile(f, "", sec("pw"), sec("pw")); err != nil {
		t.Fatal(err)
	}
	before, _ := parseHeaderV2(enc)
	after, _ := parseHeaderV2(readFile(t, f))
	if before.salt == after.salt {
		t.Fatal("rekey must use a fresh salt")
	}
}

func TestRekeyToDifferentOutputKeepsInput(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	in, out := filepath.Join(dir, "a.enc"), filepath.Join(dir, "b.enc")
	writeV1File(t, in, "data", "pw")
	before := readFile(t, in)

	if err := m.RekeyFile(in, out, sec("pw"), sec("pw")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, in), before) {
		t.Fatal("input must be untouched when -out is given")
	}
	if got, err := decryptedContent(t, m, out, sec("pw")); err != nil || got != "data" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestRekeyChangesPasswordAndKeyFile(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "old")

	// add a key file and change the password at once
	if err := m.RekeyFile(f, "", sec("old"), secKF("new", "kf")); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptedContent(t, m, f, sec("old")); err == nil {
		t.Fatal("old password must stop working")
	}
	if got, err := decryptedContent(t, m, f, secKF("new", "kf")); err != nil || got != "data" {
		t.Fatalf("%q, %v", got, err)
	}

	// and remove the key file again
	if err := m.RekeyFile(f, "", secKF("new", "kf"), sec("new")); err != nil {
		t.Fatal(err)
	}
	if got, err := decryptedContent(t, m, f, sec("new")); err != nil || got != "data" {
		t.Fatalf("%q, %v", got, err)
	}
	noTempLeftovers(t, dir)
}

func TestRekeyFailureLeavesOriginalIntact(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "right")
	orig := readFile(t, f)

	t.Run("wrong current password", func(t *testing.T) {
		err := m.RekeyFile(f, "", sec("wrong"), sec("new"))
		if err == nil || !strings.Contains(err.Error(), "decryption failed") {
			t.Fatalf("unexpected: %v", err)
		}
	})
	t.Run("empty new password", func(t *testing.T) {
		if err := m.RekeyFile(f, "", sec("right"), Secret{}); err == nil {
			t.Fatal("expected error")
		}
	})
	if !bytes.Equal(readFile(t, f), orig) {
		t.Fatal("original file was modified by a failed rekey")
	}
	noTempLeftovers(t, dir)
}

func TestRekeyCorruptSourceReportsDecryptErrorAndKeepsFile(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerWith(fastKDF, tinyChunk)
	f := filepath.Join(dir, "a.enc")
	enc, _ := newCipherV2With(fastKDF, tinyChunk).Encrypt(pattern(500), sec("pw"))
	enc[len(enc)-20] ^= 0x01
	writeFile(t, f, enc)

	err := m.RekeyFile(f, "", sec("pw"), sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("want the decryption error, got %v", err)
	}
	if !bytes.Equal(readFile(t, f), enc) {
		t.Fatal("original file was modified")
	}
	noTempLeftovers(t, dir)
}

func TestRekeyMultiChunkFile(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerWith(fastKDF, tinyChunk)
	f := filepath.Join(dir, "a.enc")
	enc, _ := newCipherV2With(fastKDF, 5).Encrypt(pattern(1000), sec("pw"))
	writeFile(t, f, enc)

	if err := m.RekeyFile(f, "", sec("pw"), sec("pw2")); err != nil {
		t.Fatal(err)
	}
	h, _ := parseHeaderV2(readFile(t, f))
	if h.chunkLog2 != tinyChunk {
		t.Fatalf("rekey should adopt the manager's current chunk size, got %d", h.chunkLog2)
	}
	out := filepath.Join(dir, "out")
	if err := m.DecryptFile(f, out, sec("pw2")); err != nil || !bytes.Equal(readFile(t, out), pattern(1000)) {
		t.Fatalf("content lost: %v", err)
	}
}

func TestRekeyRefusesStdioAndMissingFiles(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()
	if err := m.RekeyFile(StdioPath, "", sec("pw"), sec("pw")); err == nil {
		t.Fatal("stdin must be refused")
	}
	if err := m.RekeyFile(filepath.Join(dir, "a"), StdioPath, sec("pw"), sec("pw")); err == nil {
		t.Fatal("stdout must be refused")
	}
	if err := m.RekeyFile(filepath.Join(dir, "missing"), "", sec("pw"), sec("pw")); err == nil {
		t.Fatal("missing file must fail")
	}
	f := filepath.Join(dir, "plain.enc")
	writeFile(t, f, []byte{})
	if err := m.RekeyFile(f, "", sec("pw"), sec("pw")); err == nil {
		t.Fatal("empty file must fail")
	}
}

// ----------------------------------------------------------------------------
// Inspect
// ----------------------------------------------------------------------------

func TestInspectFile(t *testing.T) {
	dir := t.TempDir()
	m := fastManager()

	v1 := filepath.Join(dir, "v1.enc")
	writeFile(t, v1, mustHex(t, testvectors.V1Hex))
	if info, err := m.InspectFile(v1); err != nil || info.Version != 1 || !info.Legacy {
		t.Fatalf("%+v, %v", info, err)
	}

	v2 := filepath.Join(dir, "v2.enc")
	writeFile(t, v2, mustHex(t, testvectors.V2KeyFileHex))
	info, err := m.InspectFile(v2)
	if err != nil || info.Version != 2 || !info.KeyFile || info.ChunkSize != 64 {
		t.Fatalf("%+v, %v", info, err)
	}

	empty := filepath.Join(dir, "empty.enc")
	writeFile(t, empty, nil)
	if _, err := m.InspectFile(empty); err == nil {
		t.Fatal("empty file must fail")
	}
	bad := filepath.Join(dir, "bad.enc")
	writeFile(t, bad, []byte{9, 9, 9})
	if _, err := m.InspectFile(bad); err == nil || !strings.Contains(err.Error(), "unsupported encryption version") {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := m.InspectFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestInspectStdin(t *testing.T) {
	m, _ := stdioManager(string(mustHex(t, testvectors.V2Hex)))
	info, err := m.InspectFile(StdioPath)
	if err != nil || info.Version != 2 || info.ChunkSize != 1<<16 {
		t.Fatalf("%+v, %v", info, err)
	}
}

// ----------------------------------------------------------------------------
// Atomic writes and temp file tracking
// ----------------------------------------------------------------------------

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := writeFileAtomic(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, path)) != "two" {
		t.Fatal("content not replaced")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	}
	noTempLeftovers(t, dir)
}

func TestWriteFileAtomicTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, path, []byte("old")) // 0644
	if err := writeFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWriteFileAtomicFailureKeepsExistingAndCleansUp(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing directory", func(t *testing.T) {
		if err := writeFileAtomic(filepath.Join(dir, "nope", "f"), []byte("x"), 0600); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rename onto a directory fails", func(t *testing.T) {
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(target, "keep"), []byte("keep"))
		if err := writeFileAtomic(target, []byte("x"), 0600); err == nil {
			t.Fatal("expected error")
		}
		if string(readFile(t, filepath.Join(target, "keep"))) != "keep" {
			t.Fatal("existing target was damaged")
		}
		noTempLeftovers(t, dir)
	})

	t.Run("callback error keeps the existing file", func(t *testing.T) {
		path := filepath.Join(dir, "keepme")
		writeFile(t, path, []byte("original"))
		err := writeAtomicWith(path, 0600, func(w io.Writer) error {
			w.Write([]byte("partial"))
			return os.ErrInvalid
		})
		if !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("callback error must be returned unchanged, got %v", err)
		}
		if string(readFile(t, path)) != "original" {
			t.Fatal("existing file was modified by a failed write")
		}
		noTempLeftovers(t, dir)
	})
}

func TestTempFilesAreTrackedWhileWriting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	var during []string
	err := writeAtomicWith(path, 0600, func(w io.Writer) error {
		during = tempLeftovers(t, dir)
		temps.mu.Lock()
		tracked := len(temps.paths)
		temps.mu.Unlock()
		if tracked == 0 {
			t.Error("temp file not registered for signal cleanup")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(during) != 1 {
		t.Fatalf("expected one temp file during the write, got %v", during)
	}
	temps.mu.Lock()
	left := len(temps.paths)
	temps.mu.Unlock()
	if left != 0 {
		t.Fatal("temp file still registered after success")
	}
}

func TestRemoveTrackedTemps(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, ".casemate-a.tmp"), filepath.Join(dir, ".casemate-b.tmp")
	writeFile(t, a, []byte("x"))
	writeFile(t, b, []byte("x"))
	staging := filepath.Join(dir, ".casemate-staging.tmp")
	if err := os.MkdirAll(filepath.Join(staging, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(staging, "sub", "f"), []byte("x"))
	trackTemp(a)
	trackTemp(b)
	trackTemp(staging)
	untrackTemp(b)

	removeTrackedTemps()

	if _, err := os.Stat(a); err == nil {
		t.Fatal("tracked temp file was not removed")
	}
	if _, err := os.Stat(staging); err == nil {
		t.Fatal("tracked staging directory was not removed")
	}
	if _, err := os.Stat(b); err != nil {
		t.Fatal("untracked file must not be removed")
	}
}
