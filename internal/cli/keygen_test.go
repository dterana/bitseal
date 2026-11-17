package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIKeygenWritesUsableKeyFile(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "casemate.key")

	r := mustCLI(t, "", "keygen", "-out", key)
	if !strings.Contains(r.err, "Back it up") {
		t.Fatalf("missing backup reminder: %q", r.err)
	}
	data := readFile(t, key)
	if len(data) != keyFileSize {
		t.Fatalf("key file has %d bytes, want %d", len(data), keyFileSize)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(key)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
		}
	}

	pf := pwFile(t, dir, "a long enough passphrase")
	in := plainFile(t, dir, "a.txt", "payload")
	mustCLI(t, "", "encrypt", "-password-file", pf, "-keyfile", key, in)
	mustCLI(t, "", "decrypt", "-password-file", pf, "-keyfile", key, "-out", filepath.Join(dir, "back"), in+".enc")
	if string(readFile(t, filepath.Join(dir, "back"))) != "payload" {
		t.Fatal("round trip with a generated key file failed")
	}
}

func TestCLIKeygenKeysDiffer(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.key"), filepath.Join(dir, "b.key")
	mustCLI(t, "", "keygen", "-out", a)
	mustCLI(t, "", "keygen", "-out", b)
	if string(readFile(t, a)) == string(readFile(t, b)) {
		t.Fatal("two generated keys are identical")
	}
}

func TestCLIKeygenNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	key := plainFile(t, dir, "existing.key", "precious")

	r := cli(t, "", "keygen", "-out", key)
	if r.code != 1 || !strings.Contains(r.err, "already exists") {
		t.Fatalf("%+v", r)
	}
	if string(readFile(t, key)) != "precious" {
		t.Fatal("existing key file was modified")
	}
}

func TestCLIKeygenUsage(t *testing.T) {
	for _, args := range [][]string{
		{"keygen"},
		{"keygen", "-out", "x.key", "extra"},
	} {
		if r := cli(t, "", args...); r.code != 2 {
			t.Fatalf("%v: %+v", args, r)
		}
	}
}

func TestCLIKeygenUnwritableDirectory(t *testing.T) {
	r := cli(t, "", "keygen", "-out", filepath.Join(t.TempDir(), "missing", "x.key"))
	if r.code != 1 || !strings.Contains(r.err, "failed to create key file") {
		t.Fatalf("%+v", r)
	}
}
