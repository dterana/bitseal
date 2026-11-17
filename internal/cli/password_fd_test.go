//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pipeWith returns the read end of a pipe that already holds content. The
// caller keeps the returned file alive for as long as the descriptor is used.
func pipeWith(t *testing.T, content string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return r
}

func fdArg(r *os.File) string { return itoa(int(r.Fd())) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestCLIPasswordFD(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	pw := "a passphrase read from a descriptor"

	r := pipeWith(t, pw+"\n")
	mustCLI(t, "", "encrypt", "-password-fd", fdArg(r), in)

	r2 := pipeWith(t, pw+"\n")
	mustCLI(t, "", "decrypt", "-password-fd", fdArg(r2), "-out", filepath.Join(dir, "back"), in+".enc")
	if string(readFile(t, filepath.Join(dir, "back"))) != "payload" {
		t.Fatal("round trip through -password-fd failed")
	}
	// The caller's descriptor stays open: Casemate only closes its duplicate.
	if _, err := r2.Stat(); err != nil {
		t.Fatalf("descriptor was closed: %v", err)
	}
}

func TestCLIPasswordFDErrors(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")

	for _, fd := range []string{"0", "1", "2"} {
		r := cli(t, "", "encrypt", "-password-fd", fd, in)
		if r.code != 1 || !strings.Contains(r.err, "3 or higher") {
			t.Fatalf("fd %s: %+v", fd, r)
		}
	}
	r := cli(t, "", "encrypt", "-password-fd", "987", in)
	if r.code != 1 || !strings.Contains(r.err, "descriptor 987") {
		t.Fatalf("%+v", r)
	}
	empty := pipeWith(t, "")
	r = cli(t, "", "encrypt", "-password-fd", fdArg(empty), in)
	if r.code != 1 || !strings.Contains(r.err, "empty") {
		t.Fatalf("%+v", r)
	}
}

func TestCLIPasswordSourcesAreExclusive(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	pf := pwFile(t, dir, "a long enough passphrase")
	fd := pipeWith(t, "x\n")

	r := cli(t, "", "encrypt", "-password-file", pf, "-password-fd", fdArg(fd), in)
	if r.code != 1 || !strings.Contains(r.err, "only one of") {
		t.Fatalf("%+v", r)
	}
}

func TestCLIRekeyNewPasswordFD(t *testing.T) {
	dir := t.TempDir()
	old := pwFile(t, dir, "an old passphrase here")
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "an old passphrase here")

	nw := pipeWith(t, "a brand new passphrase\n")
	mustCLI(t, "", "rekey", "-password-file", old, "-new-password-fd", fdArg(nw), f)
	if decryptsTo(t, f, sec("a brand new passphrase")) != "data" {
		t.Fatal("new password from a descriptor was not applied")
	}
}
