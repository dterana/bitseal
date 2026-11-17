package cli

import (
	"path/filepath"
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
