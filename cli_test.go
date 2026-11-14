package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive run() in-process with a cheap KDF (see captureStdio).
// The end-to-end tests cover the compiled binary with the real parameters.

type result struct {
	out, err string
	code     int
}

func cli(t *testing.T, input string, args ...string) result {
	t.Helper()
	std := captureStdio(t, input)
	code := run(args)
	return result{std.out.String(), std.err.String(), code}
}

func cliTerminal(t *testing.T, secrets []string, args ...string) result {
	t.Helper()
	std := captureStdio(t, "")
	fakeTerminal(t, secrets...)
	code := run(args)
	return result{std.out.String(), std.err.String(), code}
}

func mustCLI(t *testing.T, input string, args ...string) result {
	t.Helper()
	r := cli(t, input, args...)
	if r.code != 0 {
		t.Fatalf("%v: code=%d stderr=%q", args, r.code, r.err)
	}
	return r
}

func pwFile(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "pw-"+strings.ReplaceAll(content, " ", "_"))
	if err := os.WriteFile(p, []byte(content+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func plainFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	writeFile(t, p, []byte(content))
	return p
}

func decryptsTo(t *testing.T, path string, s Secret) string {
	t.Helper()
	got, err := decryptedContent(t, fastManager(), path, s)
	if err != nil {
		t.Fatalf("decrypt %s: %v", path, err)
	}
	return got
}

// ----------------------------------------------------------------------------
// Top level
// ----------------------------------------------------------------------------

func TestCLINoArgsShowsUsageOnStderr(t *testing.T) {
	r := cli(t, "")
	if r.code != 1 || !strings.Contains(r.err, "Usage:") || r.out != "" {
		t.Fatalf("%+v", r)
	}
}

func TestCLIHelp(t *testing.T) {
	for _, a := range []string{"help", "-h", "--help"} {
		r := cli(t, "", a)
		if r.code != 0 || !strings.Contains(r.out, "Usage:") || !strings.Contains(r.out, "rekey") {
			t.Fatalf("%s: %+v", a, r)
		}
	}
}

func TestCLIVersion(t *testing.T) {
	for _, a := range []string{"version", "-version", "--version"} {
		r := cli(t, "", a)
		if r.code != 0 || !strings.HasPrefix(r.out, "Bitseal v"+Version) {
			t.Fatalf("%s: %+v", a, r)
		}
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	r := cli(t, "", "frobnicate")
	if r.code != 1 || !strings.Contains(r.err, "Unknown command: frobnicate") {
		t.Fatalf("%+v", r)
	}
}

func TestBuildString(t *testing.T) {
	old := Build
	defer func() { Build = old }()
	Build = "abc1234"
	if buildString() != "abc1234" {
		t.Fatal("an explicit Build must win")
	}
	Build = "dev"
	if buildString() == "" {
		t.Fatal("buildString must never be empty")
	}
}

func TestStringList(t *testing.T) {
	var l stringList
	l.Set("a")
	l.Set("b")
	if l.String() != "a,b" || len(l) != 2 {
		t.Fatalf("%v", l)
	}
}

// ----------------------------------------------------------------------------
// encrypt / decrypt
// ----------------------------------------------------------------------------

func TestCLIEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "hunter2")
	in := plainFile(t, dir, "notes.txt", "top secret\n")

	r := mustCLI(t, "", "encrypt", "-password-file", pf, "-file", in)
	if r.out != "" || !strings.Contains(r.err, "Encrypted") {
		t.Fatalf("data must stay off stdout, progress on stderr: %+v", r)
	}
	enc := readFile(t, in+".enc")
	if enc[0] != 2 || bytes.Contains(enc, []byte("top secret")) {
		t.Fatal("bad ciphertext")
	}

	os.Remove(in)
	mustCLI(t, "", "decrypt", "-password-file", pf, "-file", in+".enc")
	if string(readFile(t, in)) != "top secret\n" {
		t.Fatal("round trip mismatch")
	}
}

func TestCLIPositionalFiles(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	a := plainFile(t, dir, "a.txt", "A")
	b := plainFile(t, dir, "b.txt", "B")

	mustCLI(t, "", "encrypt", "-password-file", pf, a, b)
	os.Remove(a)
	os.Remove(b)
	mustCLI(t, "", "decrypt", "-password-file", pf, a+".enc", b+".enc")
	if string(readFile(t, a)) != "A" || string(readFile(t, b)) != "B" {
		t.Fatal("multi-file round trip failed")
	}
}

func TestCLIFileFlagRepeatableAndMixedWithPositional(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	a := plainFile(t, dir, "a.txt", "A")
	b := plainFile(t, dir, "b.txt", "B")
	c := plainFile(t, dir, "c.txt", "C")

	mustCLI(t, "", "encrypt", "-password-file", pf, "-file", a, "-file", b, c)
	for _, f := range []string{a, b, c} {
		if _, err := os.Stat(f + ".enc"); err != nil {
			t.Fatalf("%s.enc missing", f)
		}
	}
}

func TestCLICustomOutput(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	in := plainFile(t, dir, "a.txt", "payload")
	sealed, restored := filepath.Join(dir, "sealed.bin"), filepath.Join(dir, "restored.txt")

	mustCLI(t, "", "encrypt", "-password-file", pf, "-file", in, "-out", sealed)
	mustCLI(t, "", "decrypt", "-password-file", pf, "-file", sealed, "-out", restored)
	if string(readFile(t, restored)) != "payload" {
		t.Fatal("mismatch")
	}
}

func TestCLIInputValidation(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	a := plainFile(t, dir, "a.txt", "A")
	b := plainFile(t, dir, "b.txt", "B")

	cases := map[string]struct {
		args []string
		want string
	}{
		"no file":             {[]string{"encrypt", "-password-file", pf}, "no input file given"},
		"-out with many":      {[]string{"encrypt", "-password-file", pf, "-out", "x", a, b}, "-out can only be used with a single input"},
		"stdin with others":   {[]string{"encrypt", "-password-file", pf, "-", a}, "stdin (-) cannot be combined"},
		"missing file":        {[]string{"encrypt", "-password-file", pf, filepath.Join(dir, "nope")}, "failed to read file"},
		"output is input":     {[]string{"encrypt", "-password-file", pf, "-out", a, a}, "must differ"},
		"decrypt no file":     {[]string{"decrypt", "-password-file", pf}, "no input file given"},
		"decrypt missing":     {[]string{"decrypt", "-password-file", pf, filepath.Join(dir, "nope")}, "failed to read file"},
		"decrypt needs -out":  {[]string{"decrypt", "-password-file", pf, a}, "use -out"},
		"directory":           {[]string{"encrypt", "-password-file", pf, dir}, "is a directory"},
		"both password flags": {[]string{"encrypt", "-password-file", pf, "-password-env", "X", a}, "only one of"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := cli(t, "", tc.args...)
			if r.code != 1 || !strings.Contains(r.err, tc.want) {
				t.Fatalf("code=%d stderr=%q, want %q", r.code, r.err, tc.want)
			}
		})
	}
	if string(readFile(t, a)) != "A" {
		t.Fatal("input was modified")
	}
}

func TestCLIFlagParseErrorsExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{"encrypt", "-bogus"},
		{"decrypt", "-out"},
		{"rekey", "-nope", "x"},
		{"info", "-out", "x"},
	} {
		if r := cli(t, "", args...); r.code != 2 {
			t.Fatalf("%v: code=%d stderr=%q", args, r.code, r.err)
		}
	}
}

func TestCLICommandHelpExitsZero(t *testing.T) {
	for _, c := range []string{"encrypt", "decrypt", "rekey", "info"} {
		r := cli(t, "", c, "-h")
		if r.code != 0 || !strings.Contains(r.err, "-file") {
			t.Fatalf("%s -h: %+v", c, r)
		}
	}
}

func TestCLIPartialFailureProcessesTheRest(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	a := plainFile(t, dir, "a.txt", "A")
	b := plainFile(t, dir, "b.txt", "B")
	missing := filepath.Join(dir, "missing.txt")

	r := cli(t, "", "encrypt", "-password-file", pf, a, missing, b)
	if r.code != 1 || !strings.Contains(r.err, "1 of 3 files failed") || !strings.Contains(r.err, "missing.txt") {
		t.Fatalf("%+v", r)
	}
	for _, f := range []string{a, b} {
		if _, err := os.Stat(f + ".enc"); err != nil {
			t.Fatalf("%s.enc should still have been written", f)
		}
	}
}

func TestCLIWrongPassword(t *testing.T) {
	dir := t.TempDir()
	right, wrong := pwFile(t, dir, "right"), pwFile(t, dir, "wrong")
	in := plainFile(t, dir, "a.txt", "payload")
	mustCLI(t, "", "encrypt", "-password-file", right, in)

	out := filepath.Join(dir, "o")
	r := cli(t, "", "decrypt", "-password-file", wrong, "-out", out, in+".enc")
	if r.code != 1 || !strings.Contains(r.err, "decryption failed") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("plaintext written despite wrong password")
	}
}

// ----------------------------------------------------------------------------
// Password sources
// ----------------------------------------------------------------------------

func TestCLIPasswordEnv(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	t.Setenv("BITSEAL_CLI_PW", "from the environment")

	mustCLI(t, "", "encrypt", "-password-env", "BITSEAL_CLI_PW", in)
	os.Remove(in)
	mustCLI(t, "", "decrypt", "-password-env", "BITSEAL_CLI_PW", in+".enc")
	if string(readFile(t, in)) != "payload" {
		t.Fatal("mismatch")
	}

	r := cli(t, "", "encrypt", "-password-env", "BITSEAL_CLI_NOT_SET", in)
	if r.code != 1 || !strings.Contains(r.err, "BITSEAL_CLI_NOT_SET") {
		t.Fatalf("%+v", r)
	}
}

func TestCLIPipedPasswordWithSpaces(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	pw := "correct horse battery staple"

	r := mustCLI(t, pw+"\n", "encrypt", in)
	if r.out != "" || !strings.Contains(r.err, "Enter password") {
		t.Fatalf("prompt belongs on stderr: %+v", r)
	}
	if r := cli(t, "correct\n", "decrypt", "-out", filepath.Join(dir, "x"), in+".enc"); r.code != 1 {
		t.Fatal("first word alone must not decrypt")
	}
	mustCLI(t, pw+"\r\nignored\n", "decrypt", "-out", filepath.Join(dir, "y"), in+".enc")
	if string(readFile(t, filepath.Join(dir, "y"))) != "payload" {
		t.Fatal("mismatch")
	}
}

func TestCLIEmptyPasswordRejected(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	for _, input := range []string{"\n", "", "   \n"} {
		if r := cli(t, input, "encrypt", in); r.code != 1 {
			t.Fatalf("stdin=%q: %+v", input, r)
		}
	}
	if _, err := os.Stat(in + ".enc"); err == nil {
		t.Fatal("no output may be written with an empty password")
	}
}

func TestCLITerminalConfirmationMismatchWritesNothing(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	r := cliTerminal(t, []string{"one", "two"}, "encrypt", in)
	if r.code != 1 || !strings.Contains(r.err, "do not match") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(in + ".enc"); err == nil {
		t.Fatal("no output may be written")
	}
}

func TestCLITerminalConfirmationMatch(t *testing.T) {
	dir := t.TempDir()
	in := plainFile(t, dir, "a.txt", "payload")
	r := cliTerminal(t, []string{"typed pw", "typed pw"}, "encrypt", in)
	if r.code != 0 || !strings.Contains(r.err, "Confirm password") {
		t.Fatalf("%+v", r)
	}
	if decryptsTo(t, in+".enc", sec("typed pw")) != "payload" {
		t.Fatal("mismatch")
	}
	// decrypt asks only once
	r = cliTerminal(t, []string{"typed pw"}, "decrypt", "-out", filepath.Join(dir, "o"), in+".enc")
	if r.code != 0 || strings.Contains(r.err, "Confirm password") {
		t.Fatalf("%+v", r)
	}
}

// ----------------------------------------------------------------------------
// Key file
// ----------------------------------------------------------------------------

func TestCLIKeyFile(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	kf := plainFile(t, dir, "key.bin", "key file bytes")
	in := plainFile(t, dir, "a.txt", "payload")

	mustCLI(t, "", "encrypt", "-password-file", pf, "-keyfile", kf, in)

	r := cli(t, "", "decrypt", "-password-file", pf, "-out", filepath.Join(dir, "x"), in+".enc")
	if r.code != 1 || !strings.Contains(r.err, "requires a key file") {
		t.Fatalf("%+v", r)
	}
	other := plainFile(t, dir, "other.bin", "another key")
	r = cli(t, "", "decrypt", "-password-file", pf, "-keyfile", other, "-out", filepath.Join(dir, "x"), in+".enc")
	if r.code != 1 || !strings.Contains(r.err, "decryption failed") {
		t.Fatalf("%+v", r)
	}
	mustCLI(t, "", "decrypt", "-password-file", pf, "-keyfile", kf, "-out", filepath.Join(dir, "y"), in+".enc")
	if string(readFile(t, filepath.Join(dir, "y"))) != "payload" {
		t.Fatal("mismatch")
	}

	r = cli(t, "", "encrypt", "-password-file", pf, "-keyfile", filepath.Join(dir, "missing"), in)
	if r.code != 1 || !strings.Contains(r.err, "key file") {
		t.Fatalf("%+v", r)
	}
}

// ----------------------------------------------------------------------------
// stdin / stdout
// ----------------------------------------------------------------------------

func TestCLIStdinToFileAndStdoutRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	enc := filepath.Join(dir, "piped.enc")

	r := mustCLI(t, "data from a pipe", "encrypt", "-password-file", pf, "-file", "-", "-out", enc)
	if r.out != "" || !strings.Contains(r.err, "stdin") {
		t.Fatalf("%+v", r)
	}

	r = mustCLI(t, "", "decrypt", "-password-file", pf, "-file", enc, "-out", "-")
	if r.out != "data from a pipe" {
		t.Fatalf("stdout must hold exactly the plaintext, got %q", r.out)
	}
	if !strings.Contains(r.err, "Decrypted") {
		t.Fatalf("progress belongs on stderr: %q", r.err)
	}
}

func TestCLIStdinToStdoutPipeline(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	sealed := mustCLI(t, "round trip me", "encrypt", "-password-file", pf, "-file", "-").out
	if sealed == "" || sealed[0] != 2 {
		t.Fatal("encrypt - must write the encrypted file to stdout")
	}
	r := mustCLI(t, sealed, "decrypt", "-password-file", pf, "-file", "-")
	if r.out != "round trip me" {
		t.Fatalf("stdout = %q", r.out)
	}
}

func TestCLIStdinInputNeedsAnotherPasswordSource(t *testing.T) {
	for _, cmd := range []string{"encrypt", "decrypt"} {
		r := cli(t, "data", cmd, "-file", "-", "-out", filepath.Join(t.TempDir(), "o"))
		if r.code != 1 || !strings.Contains(r.err, "-password-file or -password-env") {
			t.Fatalf("%s: %+v", cmd, r)
		}
	}
}

func TestCLIRefusesBinaryToTerminal(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	in := plainFile(t, dir, "a.txt", "payload")
	std := captureStdio(t, "")
	stdoutIsTerminal = func() bool { return true }
	code := run([]string{"encrypt", "-password-file", pf, "-out", "-", in})
	if code != 1 || !strings.Contains(std.err.String(), "terminal") || std.out.Len() != 0 {
		t.Fatalf("code=%d out=%q err=%q", code, std.out.String(), std.err.String())
	}
}

func TestCLIDecryptToStdoutOnWrongPasswordPrintsNothing(t *testing.T) {
	dir := t.TempDir()
	right, wrong := pwFile(t, dir, "right"), pwFile(t, dir, "wrong")
	in := plainFile(t, dir, "a.txt", "payload")
	mustCLI(t, "", "encrypt", "-password-file", right, in)
	r := cli(t, "", "decrypt", "-password-file", wrong, "-out", "-", in+".enc")
	if r.code != 1 || r.out != "" {
		t.Fatalf("%+v", r)
	}
}

// ----------------------------------------------------------------------------
// rekey
// ----------------------------------------------------------------------------

func TestCLIRekeyUpgradesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	f := filepath.Join(dir, "legacy.enc")
	writeV1File(t, f, "legacy", "pw")

	if r := mustCLI(t, "", "info", f); !strings.Contains(r.out, "Version:   1") {
		t.Fatalf("setup: %q", r.out)
	}
	r := mustCLI(t, "", "rekey", "-password-file", pf, f)
	if !strings.Contains(r.err, "Re-encrypted") {
		t.Fatalf("%+v", r)
	}
	if r := mustCLI(t, "", "info", f); !strings.Contains(r.out, "Version:   2") {
		t.Fatalf("not upgraded: %q", r.out)
	}
	if decryptsTo(t, f, sec("pw")) != "legacy" {
		t.Fatal("content lost")
	}
}

func TestCLIRekeyToOtherOutputKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	f, out := filepath.Join(dir, "a.enc"), filepath.Join(dir, "b.enc")
	writeV1File(t, f, "x", "pw")
	before := readFile(t, f)

	mustCLI(t, "", "rekey", "-password-file", pf, "-out", out, f)
	if !bytes.Equal(readFile(t, f), before) {
		t.Fatal("original modified")
	}
	if readFile(t, out)[0] != 2 {
		t.Fatal("output should be V2")
	}
}

func TestCLIRekeyChangePasswordVariants(t *testing.T) {
	dir := t.TempDir()
	old := pwFile(t, dir, "old")
	next := pwFile(t, dir, "next")
	t.Setenv("BITSEAL_NEW_PW", "from env")

	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "old")

	mustCLI(t, "", "rekey", "-password-file", old, "-new-password-file", next, f)
	if decryptsTo(t, f, sec("next")) != "data" {
		t.Fatal("new-password-file")
	}
	if _, err := decryptedContent(t, fastManager(), f, sec("old")); err == nil {
		t.Fatal("old password must stop working")
	}

	mustCLI(t, "", "rekey", "-password-file", next, "-new-password-env", "BITSEAL_NEW_PW", f)
	if decryptsTo(t, f, sec("from env")) != "data" {
		t.Fatal("new-password-env")
	}

	// two lines on a pipe: current, then new
	mustCLI(t, "from env\nvia pipe\n", "rekey", "-change-password", f)
	if decryptsTo(t, f, sec("via pipe")) != "data" {
		t.Fatal("-change-password via pipe")
	}
}

func TestCLIRekeyChangePasswordOnTerminal(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "old")

	r := cliTerminal(t, []string{"old", "new one", "new one"}, "rekey", "-change-password", f)
	if r.code != 0 || !strings.Contains(r.err, "Current password") || !strings.Contains(r.err, "New password") || !strings.Contains(r.err, "Confirm new password") {
		t.Fatalf("%+v", r)
	}
	if decryptsTo(t, f, sec("new one")) != "data" {
		t.Fatal("password not changed")
	}

	before := readFile(t, f)
	r = cliTerminal(t, []string{"new one", "a", "b"}, "rekey", "-change-password", f)
	if r.code != 1 || !strings.Contains(r.err, "do not match") {
		t.Fatalf("%+v", r)
	}
	if !bytes.Equal(readFile(t, f), before) {
		t.Fatal("file modified despite mismatched confirmation")
	}
}

func TestCLIRekeyKeyFileAddReplaceRemove(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	kf1 := plainFile(t, dir, "k1", "first key")
	kf2 := plainFile(t, dir, "k2", "second key")
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "pw")

	mustCLI(t, "", "rekey", "-password-file", pf, "-new-keyfile", kf1, f)
	if r := mustCLI(t, "", "info", f); !strings.Contains(r.out, "Key file:  required") {
		t.Fatalf("%q", r.out)
	}
	if decryptsTo(t, f, secKF("pw", "first key")) != "data" {
		t.Fatal("add")
	}

	mustCLI(t, "", "rekey", "-password-file", pf, "-keyfile", kf1, "-new-keyfile", kf2, f)
	if decryptsTo(t, f, secKF("pw", "second key")) != "data" {
		t.Fatal("replace")
	}

	// keep the key file when only the password changes
	next := pwFile(t, dir, "next")
	mustCLI(t, "", "rekey", "-password-file", pf, "-keyfile", kf2, "-new-password-file", next, f)
	if decryptsTo(t, f, secKF("next", "second key")) != "data" {
		t.Fatal("key file should be kept when only the password changes")
	}

	mustCLI(t, "", "rekey", "-password-file", next, "-keyfile", kf2, "-no-keyfile", f)
	if r := mustCLI(t, "", "info", f); !strings.Contains(r.out, "Key file:  not required") {
		t.Fatalf("%q", r.out)
	}
	if decryptsTo(t, f, sec("next")) != "data" {
		t.Fatal("remove")
	}
}

func TestCLIRekeyErrors(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	other := pwFile(t, dir, "other")
	kf := plainFile(t, dir, "k", "key")
	f := filepath.Join(dir, "a.enc")
	writeV1File(t, f, "data", "pw")
	orig := readFile(t, f)
	t.Setenv("BITSEAL_X", "x")

	cases := map[string]struct {
		args []string
		want string
	}{
		"wrong password":      {[]string{"rekey", "-password-file", other, f}, "decryption failed"},
		"stdin":               {[]string{"rekey", "-password-file", pf, "-"}, "files only"},
		"no file":             {[]string{"rekey", "-password-file", pf}, "no input file given"},
		"both new passwords":  {[]string{"rekey", "-password-file", pf, "-new-password-file", other, "-new-password-env", "BITSEAL_X", f}, "only one of -new-password-file"},
		"keyfile conflict":    {[]string{"rekey", "-password-file", pf, "-no-keyfile", "-new-keyfile", kf, f}, "cannot be combined"},
		"missing new keyfile": {[]string{"rekey", "-password-file", pf, "-new-keyfile", filepath.Join(dir, "nope"), f}, "key file"},
		"missing file":        {[]string{"rekey", "-password-file", pf, filepath.Join(dir, "nope.enc")}, "failed to read file"},
		"missing new pw file": {[]string{"rekey", "-password-file", pf, "-new-password-file", filepath.Join(dir, "nope"), f}, "password file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := cli(t, "", tc.args...)
			if r.code != 1 || !strings.Contains(r.err, tc.want) {
				t.Fatalf("code=%d stderr=%q, want %q", r.code, r.err, tc.want)
			}
		})
	}
	if !bytes.Equal(readFile(t, f), orig) {
		t.Fatal("file modified by a failed rekey")
	}
	noTempLeftovers(t, dir)
}

func TestCLIRekeyPartialFailure(t *testing.T) {
	dir := t.TempDir()
	pf := pwFile(t, dir, "pw")
	a, b := filepath.Join(dir, "a.enc"), filepath.Join(dir, "b.enc")
	writeV1File(t, a, "A", "pw")
	writeV1File(t, b, "B", "other")

	r := cli(t, "", "rekey", "-password-file", pf, a, b)
	if r.code != 1 || !strings.Contains(r.err, "1 of 2 files failed") {
		t.Fatalf("%+v", r)
	}
	if readFile(t, a)[0] != 2 || readFile(t, b)[0] != 1 {
		t.Fatal("only the file with the right password should have been upgraded")
	}
}

// ----------------------------------------------------------------------------
// info
// ----------------------------------------------------------------------------

func TestCLIInfoLegacyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "legacy.enc")
	writeFile(t, f, mustHex(t, goldenV1Hex))

	r := mustCLI(t, "", "info", f)
	for _, want := range []string{"Version:   1", "PBKDF2", "static salt", "legacy", "bitseal rekey", "File:      " + f} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("info lacks %q:\n%s", want, r.out)
		}
	}
	if r.err != "" {
		t.Fatalf("successful info must not write to stderr: %q", r.err)
	}
}

func TestCLIInfoCurrentFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "v2.enc")
	writeFile(t, f, mustHex(t, goldenV2Hex))

	r := mustCLI(t, "", "info", "-file", f)
	for _, want := range []string{"Version:   2", "Argon2id", "time=3", "memory=64 MiB", "threads=4", "64 KiB chunks", "Key file:  not required"} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("info lacks %q:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "legacy") {
		t.Fatal("V2 must not be flagged as legacy")
	}
}

func TestCLIInfoSmallChunksAndKeyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "kf.enc")
	writeFile(t, f, mustHex(t, goldenV2MultiHex))
	r := mustCLI(t, "", "info", f)
	if !strings.Contains(r.out, "16 byte chunks") {
		t.Fatalf("%s", r.out)
	}
	writeFile(t, f, mustHex(t, goldenV2KeyFileHex))
	if r := mustCLI(t, "", "info", f); !strings.Contains(r.out, "Key file:  required") {
		t.Fatalf("%s", r.out)
	}
}

func TestCLIInfoMultipleFilesAndErrors(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.enc"), filepath.Join(dir, "b.enc")
	writeFile(t, a, mustHex(t, goldenV1Hex))
	writeFile(t, b, mustHex(t, goldenV2Hex))

	r := mustCLI(t, "", "info", a, b)
	if strings.Count(r.out, "File:") != 2 || !strings.Contains(r.out, "\n\nFile:") {
		t.Fatalf("expected two blocks separated by a blank line:\n%s", r.out)
	}

	bad := filepath.Join(dir, "bad.enc")
	writeFile(t, bad, []byte("not encrypted"))
	r = cli(t, "", "info", a, bad, filepath.Join(dir, "missing"))
	if r.code != 1 || !strings.Contains(r.err, "Info error") || !strings.Contains(r.err, "2 of 3 files failed") {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.out, "Version:   1") {
		t.Fatal("the readable file must still be reported")
	}
}

func TestCLIInfoFromStdin(t *testing.T) {
	r := mustCLI(t, string(mustHex(t, goldenV2Hex)), "info", "-file", "-")
	if !strings.Contains(r.out, "File:      stdin") || !strings.Contains(r.out, "Version:   2") {
		t.Fatalf("%s", r.out)
	}
}

func TestCLIInfoNeedsNoPassword(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "v2.enc")
	writeFile(t, f, mustHex(t, goldenV2Hex))
	r := cli(t, "", "info", f) // stdin is empty: any password prompt would fail
	if r.code != 0 || strings.Contains(r.err, "password") {
		t.Fatalf("%+v", r)
	}
}
