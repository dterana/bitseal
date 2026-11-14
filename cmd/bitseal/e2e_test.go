package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dterana/bitseal/internal/testvectors"
)

// End-to-end tests run the compiled binary with the real Argon2 parameters,
// real pipes and real exit codes.

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

type binResult struct {
	stdout, stderr string
	code           int
}

// runBin executes the binary with stdin piped (non-terminal) and optional
// extra environment variables.
func runBin(t *testing.T, stdin string, env []string, args ...string) binResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("failed to run binary: %v", err)
		}
		code = ee.ExitCode()
	}
	return binResult{out.String(), errb.String(), code}
}

func mustBin(t *testing.T, stdin string, env []string, args ...string) binResult {
	t.Helper()
	r := runBin(t, stdin, env, args...)
	if r.code != 0 {
		t.Fatalf("%v: code=%d stderr=%q", args, r.code, r.stderr)
	}
	return r
}

func TestE2EVersion(t *testing.T) {
	for _, flag := range []string{"version", "-version", "--version"} {
		r := runBin(t, "", nil, flag)
		if r.code != 0 || !strings.Contains(r.stdout, "Bitseal v"+Version) {
			t.Fatalf("%s: %+v", flag, r)
		}
	}
}

func TestE2EUsageAndUnknownCommand(t *testing.T) {
	if r := runBin(t, "", nil); r.code != 1 || !strings.Contains(r.stderr, "Usage:") {
		t.Fatalf("%+v", r)
	}
	if r := runBin(t, "", nil, "frobnicate"); r.code != 1 || !strings.Contains(r.stderr, "Unknown command") {
		t.Fatalf("%+v", r)
	}
	if r := runBin(t, "pw\n", nil, "encrypt"); r.code != 1 || !strings.Contains(r.stderr, "no input file") {
		t.Fatalf("%+v", r)
	}
	if r := runBin(t, "", nil, "encrypt", "-bogus"); r.code != 2 {
		t.Fatalf("flag errors must exit 2: %+v", r)
	}
	if r := runBin(t, "", nil, "help"); r.code != 0 || !strings.Contains(r.stdout, "rekey") {
		t.Fatalf("%+v", r)
	}
}

func TestE2EEncryptDecryptRoundTripWithDefaultParameters(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "notes.txt")
	writeFile(t, in, []byte("top secret\n"))

	r := mustBin(t, "hunter2\n", nil, "encrypt", in)
	if r.stdout != "" || !strings.Contains(r.stderr, "Encrypted") {
		t.Fatalf("%+v", r)
	}

	// the binary must write the documented defaults into the header
	info := mustBin(t, "", nil, "info", in+".enc").stdout
	for _, want := range []string{"Version:   2", "time=3", "memory=64 MiB", "threads=4", "64 KiB chunks"} {
		if !strings.Contains(info, want) {
			t.Fatalf("info lacks %q:\n%s", want, info)
		}
	}
	if bytes.Contains(readFile(t, in+".enc"), []byte("top secret")) {
		t.Fatal("plaintext leaked into the encrypted file")
	}

	os.Remove(in)
	mustBin(t, "hunter2\n", nil, "decrypt", in+".enc")
	if string(readFile(t, in)) != "top secret\n" {
		t.Fatal("round trip mismatch")
	}
}

func TestE2EWrongPasswordAndNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	mustBin(t, "right\n", nil, "encrypt", in)

	out := filepath.Join(dir, "o")
	r := runBin(t, "wrong\n", nil, "decrypt", "-out", out, in+".enc")
	if r.code != 1 || !strings.Contains(r.stderr, "decryption failed") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("plaintext written despite wrong password")
	}
	noTempLeftovers(t, dir)
}

func TestE2EStdoutCarriesOnlyData(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("exact bytes\n"))
	mustBin(t, "pw\n", nil, "encrypt", in)

	r := mustBin(t, "pw\n", nil, "decrypt", "-out", "-", in+".enc")
	if r.stdout != "exact bytes\n" {
		t.Fatalf("stdout must hold exactly the plaintext, got %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "Enter password") {
		t.Fatalf("the prompt belongs on stderr: %q", r.stderr)
	}
}

func TestE2EPipeline(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "pw")
	os.WriteFile(pf, []byte("pipeline pw\n"), 0600)

	sealed := mustBin(t, "streamed through a pipe", nil, "encrypt", "-password-file", pf, "-file", "-").stdout
	if len(sealed) == 0 || sealed[0] != 2 {
		t.Fatal("encrypt - must write an encrypted file to stdout")
	}
	r := mustBin(t, sealed, nil, "decrypt", "-password-file", pf, "-file", "-")
	if r.stdout != "streamed through a pipe" {
		t.Fatalf("stdout = %q", r.stdout)
	}
}

func TestE2EPasswordFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	pf := filepath.Join(dir, "pw")
	os.WriteFile(pf, []byte("correct horse battery staple\n"), 0600)

	mustBin(t, "", nil, "encrypt", "-password-file", pf, in)
	// the same passphrase through the environment opens it
	r := mustBin(t, "", []string{"BITSEAL_E2E_PW=correct horse battery staple"}, "decrypt", "-password-env", "BITSEAL_E2E_PW", "-out", "-", in+".enc")
	if r.stdout != "payload" {
		t.Fatalf("stdout = %q", r.stdout)
	}
	if r := runBin(t, "", nil, "decrypt", "-password-env", "BITSEAL_E2E_NOT_SET", in+".enc"); r.code != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestE2EKeyFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	pf := filepath.Join(dir, "pw")
	os.WriteFile(pf, []byte("pw\n"), 0600)
	kf := filepath.Join(dir, "key.bin")
	writeFile(t, kf, pattern(64))

	mustBin(t, "", nil, "encrypt", "-password-file", pf, "-keyfile", kf, in)
	if r := runBin(t, "", nil, "decrypt", "-password-file", pf, "-out", "-", in+".enc"); r.code != 1 || !strings.Contains(r.stderr, "requires a key file") {
		t.Fatalf("%+v", r)
	}
	if r := mustBin(t, "", nil, "decrypt", "-password-file", pf, "-keyfile", kf, "-out", "-", in+".enc"); r.stdout != "payload" {
		t.Fatalf("stdout = %q", r.stdout)
	}
	if r := mustBin(t, "", nil, "info", in+".enc"); !strings.Contains(r.stdout, "Key file:  required") {
		t.Fatalf("%s", r.stdout)
	}
}

func TestE2EGoldenFilesDecryptWithDefaultParameters(t *testing.T) {
	dir := t.TempDir()
	for name, h := range map[string]string{"v1": testvectors.V1Hex, "v2": testvectors.V2Hex} {
		in := filepath.Join(dir, name+".enc")
		writeFile(t, in, mustHex(t, h))
		r := mustBin(t, testvectors.Password+"\n", nil, "decrypt", "-out", "-", in)
		if r.stdout != testvectors.Plaintext {
			t.Fatalf("%s: stdout = %q", name, r.stdout)
		}
	}
}

func TestE2ELegacyFileUpgradeWorkflow(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "legacy.enc")
	writeFile(t, f, mustHex(t, testvectors.V1Hex))

	r := mustBin(t, "", nil, "info", f)
	if !strings.Contains(r.stdout, "Version:   1") || !strings.Contains(r.stdout, "bitseal rekey") {
		t.Fatalf("%s", r.stdout)
	}

	mustBin(t, testvectors.Password+"\n", nil, "rekey", f)

	r = mustBin(t, "", nil, "info", f)
	if !strings.Contains(r.stdout, "Version:   2") || !strings.Contains(r.stdout, "Argon2id") {
		t.Fatalf("not upgraded:\n%s", r.stdout)
	}
	if r := mustBin(t, testvectors.Password+"\n", nil, "decrypt", "-out", "-", f); r.stdout != testvectors.Plaintext {
		t.Fatalf("content lost: %q", r.stdout)
	}
	noTempLeftovers(t, dir)
}

func TestE2ERekeyChangePasswordPiped(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("payload"))
	mustBin(t, "old\n", nil, "encrypt", in)

	// current password on the first line, new password on the second
	mustBin(t, "old\nnew\n", nil, "rekey", "-change-password", in+".enc")
	if r := runBin(t, "old\n", nil, "decrypt", "-out", "-", in+".enc"); r.code != 1 {
		t.Fatal("the old password must stop working")
	}
	if r := mustBin(t, "new\n", nil, "decrypt", "-out", "-", in+".enc"); r.stdout != "payload" {
		t.Fatalf("stdout = %q", r.stdout)
	}
}

func TestE2EInfoOnGoldenFiles(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "v2.enc")
	writeFile(t, f, mustHex(t, testvectors.V2Hex))
	r := mustBin(t, "", nil, "info", f)
	for _, want := range []string{"Version:   2", "time=3", "memory=64 MiB", "threads=4", "64 KiB chunks"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("info lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestE2EDirectoryInputRefused(t *testing.T) {
	dir := t.TempDir()
	r := runBin(t, "pw\n", nil, "encrypt", dir)
	if r.code != 1 || !strings.Contains(r.stderr, "is a directory") {
		t.Fatalf("%+v", r)
	}
}

func TestE2ELargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("large file skipped in short mode")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "blob")
	data := pattern(3<<20 + 77)
	writeFile(t, in, data)

	mustBin(t, "pw\n", nil, "encrypt", in)
	out := filepath.Join(dir, "blob.out")
	mustBin(t, "pw\n", nil, "decrypt", "-out", out, in+".enc")
	if !bytes.Equal(readFile(t, out), data) {
		t.Fatal("round trip mismatch")
	}
	noTempLeftovers(t, dir)
}

func TestE2EOutputsDifferPerRun(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("same content"))
	mustBin(t, "pw\n", nil, "encrypt", "-out", filepath.Join(dir, "1.enc"), in)
	mustBin(t, "pw\n", nil, "encrypt", "-out", filepath.Join(dir, "2.enc"), in)
	if bytes.Equal(readFile(t, filepath.Join(dir, "1.enc")), readFile(t, filepath.Join(dir, "2.enc"))) {
		t.Fatal("two encryptions must differ (salt and nonce)")
	}
}

// An interrupt in the middle of a write must remove the temp file and leave
// no output behind.
func TestE2ESigintRemovesTempFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals differ on windows")
	}
	dir := t.TempDir()
	pf := filepath.Join(dir, "pw")
	os.WriteFile(pf, []byte("pw\n"), 0600)
	out := filepath.Join(dir, "o.enc")

	cmd := exec.Command(binPath, "encrypt", "-password-file", pf, "-file", "-", "-out", out)
	stdinPipe, err := cmd.StdinPipe() // stays open, so the encrypt blocks mid-write
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer stdinPipe.Close()

	deadline := time.Now().Add(15 * time.Second)
	for len(tempLeftovers(t, dir)) == 0 {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("temp file never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	werr := cmd.Wait()
	var ee *exec.ExitError
	if !errors.As(werr, &ee) || ee.ExitCode() != 130 {
		t.Fatalf("expected exit code 130, got %v", werr)
	}
	noTempLeftovers(t, dir)
	if _, err := os.Stat(out); err == nil {
		t.Fatal("output must not exist after an interrupt")
	}
}
