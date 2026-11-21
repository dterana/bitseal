package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIWarnsAboutShortNewPasswords(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")

	short := pwFile(t, dir, "short")
	r := mustCLI(t, "", "encrypt", "-password-file", short, in)
	if !strings.Contains(r.err, "only 5 characters") {
		t.Fatalf("no warning for a short password: %q", r.err)
	}
	// The password is still accepted.
	if decryptsTo(t, in+".enc", sec("short")) != "payload" {
		t.Fatal("short password must still work")
	}

	long := pwFile(t, dir, "a long enough passphrase")
	r = mustCLI(t, "", "encrypt", "-password-file", long, "-out", filepath.Join(dir, "b.enc"), in)
	if strings.Contains(r.err, "Warning:") {
		t.Fatalf("unexpected warning for a long password: %q", r.err)
	}
}

func TestCLINoWarningWhenDecrypting(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	short := pwFile(t, dir, "short")
	mustCLI(t, "", "encrypt", "-password-file", short, in)

	r := mustCLI(t, "", "decrypt", "-password-file", short, "-out", filepath.Join(dir, "back"), in+".enc")
	if strings.Contains(r.err, "Warning:") {
		t.Fatalf("decrypt must not warn: %q", r.err)
	}
}

func TestCLIRekeyWarnsOnlyWhenPasswordChanges(t *testing.T) {
	dir := t.TempDir()
	cur := pwFile(t, dir, "cur")
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "cur")

	r := mustCLI(t, "", "rekey", "-password-file", cur, f)
	if strings.Contains(r.err, "Warning:") {
		t.Fatalf("rekey without a new password must not warn: %q", r.err)
	}

	next := pwFile(t, dir, "tiny")
	r = mustCLI(t, "", "rekey", "-password-file", cur, "-new-password-file", next, f)
	if !strings.Contains(r.err, "only 4 characters") {
		t.Fatalf("no warning for a short new password: %q", r.err)
	}
}

func TestCLIShortWarningCountsCharactersNotBytes(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	// 12 characters, 24+ bytes: long enough.
	pf := pwFile(t, dir, "日本語日本語日本語日本語")
	r := mustCLI(t, "", "encrypt", "-password-file", pf, in)
	if strings.Contains(r.err, "Warning:") {
		t.Fatalf("12 multi-byte characters must not warn: %q", r.err)
	}
}

func TestCLIStrictRefusesShortNewPasswords(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")

	short := pwFile(t, dir, "short")
	r := cli(t, "", "encrypt", "-strict", "-password-file", short, in)
	if r.code == 0 || !strings.Contains(r.err, "-strict requires 12") {
		t.Fatalf("strict must refuse a short password: code=%d %q", r.code, r.err)
	}
	if _, err := os.Stat(in + ".enc"); err == nil {
		t.Fatal("nothing must be written when strict refuses")
	}

	long := pwFile(t, dir, "a long enough passphrase")
	mustCLI(t, "", "encrypt", "-strict", "-password-file", long, in)

	// Decrypting an older file protected by a short password stays possible.
	old := filepath.Join(dir, "old.enc")
	writeV1File(t, old, "data", "cur")
	cur := pwFile(t, dir, "cur")
	mustCLI(t, "", "decrypt", "-strict", "-password-file", cur, "-out", filepath.Join(dir, "old.txt"), old)
}

func TestCLIStrictRefusesShortNewPasswordOnRekey(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "cur")
	cur := pwFile(t, dir, "cur")
	next := pwFile(t, dir, "tiny")

	r := cli(t, "", "rekey", "-strict", "-password-file", cur, "-new-password-file", next, f)
	if r.code == 0 || !strings.Contains(r.err, "-strict requires 12") {
		t.Fatalf("strict rekey must refuse a short new password: code=%d %q", r.code, r.err)
	}
}

func TestCLIStrictRefusesLooseSecretFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	loose := pwFile(t, dir, "a long enough passphrase")
	if err := os.Chmod(loose, 0644); err != nil {
		t.Fatal(err)
	}

	r := cli(t, "", "encrypt", "-strict", "-password-file", loose, in)
	if r.code == 0 || !strings.Contains(r.err, "accessible by other users (-strict)") {
		t.Fatalf("strict must refuse a loose password file: code=%d %q", r.code, r.err)
	}
	// Without -strict it is still only a warning.
	mustCLI(t, "", "encrypt", "-password-file", loose, in)
}
