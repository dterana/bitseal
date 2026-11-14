package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bitseal-e2e")
	if err != nil {
		panic(err)
	}
	name := "bitseal"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(dir, name)
	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		panic("build failed: " + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// run executes the built binary with stdin piped (non-terminal), so the
// password is read through the plain-input fallback.
func run(t *testing.T, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("failed to run binary: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), code
}

func TestE2EVersionFlag(t *testing.T) {
	for _, flag := range []string{"-version", "--version"} {
		out, code := run(t, "", flag)
		if code != 0 || !strings.Contains(out, "Bitseal v"+Version) {
			t.Fatalf("%s: code=%d out=%q", flag, code, out)
		}
	}
}

func TestE2ENoArgsShowsUsage(t *testing.T) {
	out, code := run(t, "")
	if code != 1 || !strings.Contains(out, "Usage:") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestE2EUnknownCommand(t *testing.T) {
	out, code := run(t, "", "frobnicate")
	if code != 1 || !strings.Contains(out, "Unknown command") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestE2EMissingFileFlag(t *testing.T) {
	for _, cmd := range []string{"encrypt", "decrypt"} {
		out, code := run(t, "pw\n", cmd)
		if code != 1 || !strings.Contains(out, "-file flag required") {
			t.Fatalf("%s: code=%d out=%q", cmd, code, out)
		}
	}
}

func TestE2EEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "notes.txt")
	writeFile(t, in, []byte("top secret\n"))

	out, code := run(t, "hunter2\n", "encrypt", "-file", in)
	if code != 0 || !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("encrypt: code=%d out=%q", code, out)
	}
	enc := readFile(t, in+".enc")
	if enc[0] != 2 {
		t.Fatalf("CLI must write V2, got version %d", enc[0])
	}
	if bytes.Contains(enc, []byte("top secret")) {
		t.Fatal("plaintext leaked into encrypted file")
	}

	os.Remove(in)
	out, code = run(t, "hunter2\n", "decrypt", "-file", in+".enc")
	if code != 0 || !strings.Contains(out, "decrypted successfully") {
		t.Fatalf("decrypt: code=%d out=%q", code, out)
	}
	if string(readFile(t, in)) != "top secret\n" {
		t.Fatal("round trip mismatch")
	}
}

func TestE2ECustomOutputPaths(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	enc := filepath.Join(dir, "sealed.bin")
	dec := filepath.Join(dir, "restored.txt")
	writeFile(t, in, []byte("payload"))

	if _, code := run(t, "pw\n", "encrypt", "-file", in, "-out", enc); code != 0 {
		t.Fatal("encrypt failed")
	}
	if _, code := run(t, "pw\n", "decrypt", "-file", enc, "-out", dec); code != 0 {
		t.Fatal("decrypt failed")
	}
	if string(readFile(t, dec)) != "payload" {
		t.Fatal("mismatch")
	}
}

func TestE2EPasswordWithoutTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	if _, code := run(t, "pw", "encrypt", "-file", in); code != 0 {
		t.Fatal("encrypt failed with EOF-terminated password")
	}
	os.Remove(in)
	if _, code := run(t, "pw", "decrypt", "-file", in+".enc"); code != 0 {
		t.Fatal("decrypt failed with EOF-terminated password")
	}
	if string(readFile(t, in)) != "payload" {
		t.Fatal("mismatch")
	}
}

func TestE2EWrongPassword(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	run(t, "right\n", "encrypt", "-file", in)

	out, code := run(t, "wrong\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "o"))
	if code != 1 || !strings.Contains(out, "decryption failed") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "o")); err == nil {
		t.Fatal("plaintext written despite wrong password")
	}
}

func TestE2EEmptyPasswordRejected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	for _, stdin := range []string{"\n", ""} {
		out, code := run(t, stdin, "encrypt", "-file", in)
		if code != 1 {
			t.Fatalf("stdin=%q: expected exit 1, got %d (%q)", stdin, code, out)
		}
		if _, err := os.Stat(in + ".enc"); err == nil {
			t.Fatal("no output may be written with an empty password")
		}
	}
}

func TestE2EMissingInputFile(t *testing.T) {
	dir := t.TempDir()
	for _, cmd := range []string{"encrypt", "decrypt"} {
		out, code := run(t, "pw\n", cmd, "-file", filepath.Join(dir, "nope"))
		if code != 1 || !strings.Contains(out, "failed to read file") {
			t.Fatalf("%s: code=%d out=%q", cmd, code, out)
		}
	}
}

func TestE2EDecryptCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	run(t, "pw\n", "encrypt", "-file", in)

	enc := readFile(t, in+".enc")
	enc[len(enc)-1] ^= 0xFF
	bad := filepath.Join(dir, "bad.enc")
	writeFile(t, bad, enc)

	out, code := run(t, "pw\n", "decrypt", "-file", bad, "-out", filepath.Join(dir, "o"))
	if code != 1 || !strings.Contains(out, "decryption failed") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestE2EDecryptUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "future.enc")
	writeFile(t, in, append([]byte{9}, make([]byte, 64)...))
	out, code := run(t, "pw\n", "decrypt", "-file", in)
	if code != 1 || !strings.Contains(out, "unsupported encryption version: 9") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestE2EDecryptLegacyV1File(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "legacy.enc")
	writeFile(t, in, mustHex(t, goldenV1Hex))
	out := filepath.Join(dir, "legacy.txt")
	if _, code := run(t, "golden-pw\n", "decrypt", "-file", in, "-out", out); code != 0 {
		t.Fatal("legacy V1 file must still decrypt via the CLI")
	}
	if string(readFile(t, out)) != "golden plaintext" {
		t.Fatal("mismatch")
	}
}

func TestE2EDecryptGoldenV2File(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "v2.enc")
	writeFile(t, in, mustHex(t, goldenV2Hex))
	out := filepath.Join(dir, "v2.txt")
	if _, code := run(t, "golden-pw\n", "decrypt", "-file", in, "-out", out); code != 0 {
		t.Fatal("golden V2 file must decrypt via the CLI")
	}
	if string(readFile(t, out)) != "golden plaintext" {
		t.Fatal("mismatch")
	}
}

func TestE2ERandomizedOutputPerRun(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("same content"))
	run(t, "pw\n", "encrypt", "-file", in, "-out", filepath.Join(dir, "1.enc"))
	run(t, "pw\n", "encrypt", "-file", in, "-out", filepath.Join(dir, "2.enc"))
	if bytes.Equal(readFile(t, filepath.Join(dir, "1.enc")), readFile(t, filepath.Join(dir, "2.enc"))) {
		t.Fatal("two CLI encryptions must differ (salt and nonce)")
	}
}

func TestE2EBinaryAndLargeFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "blob")
	if testing.Short() {
		t.Skip("large file test skipped in short mode")
	}
	data := make([]byte, 3<<20)
	for i := range data {
		data[i] = byte(i * 31)
	}
	writeFile(t, in, data)
	if _, code := run(t, "pw\n", "encrypt", "-file", in); code != 0 {
		t.Fatal("encrypt failed")
	}
	out := filepath.Join(dir, "blob.out")
	if _, code := run(t, "pw\n", "decrypt", "-file", in+".enc", "-out", out); code != 0 {
		t.Fatal("decrypt failed")
	}
	if !bytes.Equal(readFile(t, out), data) {
		t.Fatal("binary round trip mismatch")
	}
}

func TestE2EEnvFileUseCase(t *testing.T) {
	// The genesis use case: an encrypted env file rendered into a config dir.
	dir := t.TempDir()
	src := filepath.Join(dir, "ngrok.yml")
	writeFile(t, src, []byte("authtoken: abc123\n"))
	if _, code := run(t, "pw\n", "encrypt", "-file", src); code != 0 {
		t.Fatal("encrypt failed")
	}
	os.Remove(src)

	target := filepath.Join(dir, "config", "ngrok.yml")
	os.MkdirAll(filepath.Dir(target), 0700)
	if _, code := run(t, "pw\n", "decrypt", "-file", src+".enc", "-out", target); code != 0 {
		t.Fatal("decrypt failed")
	}
	if string(readFile(t, target)) != "authtoken: abc123\n" {
		t.Fatal("mismatch")
	}
}

func TestE2EPasswordWithSpaces(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	pw := "correct horse battery staple"

	if out, code := run(t, pw+"\n", "encrypt", "-file", in); code != 0 {
		t.Fatalf("encrypt: code=%d out=%q", code, out)
	}
	// the same passphrase must open the file, and only its first word must not
	if out, code := run(t, "correct\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "x")); code != 1 {
		t.Fatalf("first word alone must not decrypt: code=%d out=%q", code, out)
	}
	if out, code := run(t, pw+"\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "y")); code != 0 {
		t.Fatalf("decrypt: code=%d out=%q", code, out)
	}
	if string(readFile(t, filepath.Join(dir, "y"))) != "payload" {
		t.Fatal("mismatch")
	}
}

func TestE2EPasswordLineEndingsAndTrailingInput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	// CRLF and extra lines after the password must not change the password
	if _, code := run(t, "pw\r\nignored\n", "encrypt", "-file", in); code != 0 {
		t.Fatal("encrypt failed")
	}
	if _, code := run(t, "pw\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "o")); code != 0 {
		t.Fatal("password with CRLF should equal the plain password")
	}
}

func TestE2EDecryptWithoutEncExtensionRequiresOut(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	sealed := filepath.Join(dir, "sealed.bin")
	if _, code := run(t, "pw\n", "encrypt", "-file", in, "-out", sealed); code != 0 {
		t.Fatal("encrypt failed")
	}
	before := readFile(t, sealed)

	out, code := run(t, "pw\n", "decrypt", "-file", sealed)
	if code != 1 || !strings.Contains(out, "use -out") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if !bytes.Equal(readFile(t, sealed), before) {
		t.Fatal("encrypted file must not be modified")
	}
}

func TestE2EOutputEqualsInputRefused(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	out, code := run(t, "pw\n", "encrypt", "-file", in, "-out", in)
	if code != 1 || !strings.Contains(out, "must differ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if string(readFile(t, in)) != "payload" {
		t.Fatal("input was clobbered")
	}
}

func TestE2ENoTempFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	run(t, "pw\n", "encrypt", "-file", in)
	run(t, "wrong\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "o"))
	run(t, "pw\n", "decrypt", "-file", in+".enc", "-out", filepath.Join(dir, "o"))
	if l := tempLeftovers(t, dir); len(l) != 0 {
		t.Fatalf("temp files left behind: %v", l)
	}
}
