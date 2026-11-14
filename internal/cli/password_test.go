package cli

import (
	"bytes"
	"errors"
	"github.com/dterana/bitseal/internal/seal"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadPasswordLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"simple", "pw\n", "pw", false},
		{"no trailing newline", "pw", "pw", false},
		{"crlf", "pw\r\n", "pw", false},
		{"spaces inside preserved", "correct horse battery staple\n", "correct horse battery staple", false},
		{"surrounding whitespace trimmed", "  pw  \n", "pw", false},
		{"only first line used", "first\nsecond\n", "first", false},
		{"unicode", "pässwörd 日本語\n", "pässwörd 日本語", false},
		{"long", strings.Repeat("x", 100000) + "\n", strings.Repeat("x", 100000), false},
		{"empty input", "", "", true},
		{"empty line", "\n", "", true},
		{"whitespace only", "   \t \n", "", true},
		{"crlf only", "\r\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPasswordLine(strings.NewReader(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadPasswordLineReadError(t *testing.T) {
	if _, err := readPasswordLine(failingReader{}); err == nil || !strings.Contains(err.Error(), "failed to read password") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCleanPasswordReturnsIndependentCopy(t *testing.T) {
	in := []byte("  secret  ")
	got, err := cleanPassword(in)
	if err != nil {
		t.Fatal(err)
	}
	seal.Wipe(in)
	if string(got) != "secret" {
		t.Fatalf("wiping the input changed the result: %q", got)
	}
}

func TestReadPasswordPiped(t *testing.T) {
	std := captureStdio(t, "hello world\n")
	got, err := std.promptPassword("Enter password: ")
	if err != nil || string(got) != "hello world" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestPromptGoesToStderrNotStdout(t *testing.T) {
	std := captureStdio(t, "pw\n")
	if _, err := std.promptPassword("Enter password: "); err != nil {
		t.Fatal(err)
	}
	if std.out.Len() != 0 {
		t.Fatalf("prompt leaked to stdout: %q", std.out.String())
	}
	if !strings.Contains(std.err.String(), "Enter password") {
		t.Fatalf("prompt missing from stderr: %q", std.err.String())
	}
}

// Two prompts on one pipe (current and new password) must each get their own
// line; the first read must not swallow the second.
func TestSeveralPromptsShareOnePipe(t *testing.T) {
	std := captureStdio(t, "first\nsecond\nthird\n")
	for _, want := range []string{"first", "second", "third"} {
		got, err := std.promptPassword("> ")
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	if _, err := std.promptPassword("> "); err == nil {
		t.Fatal("pipe is exhausted, expected an error")
	}
}

func TestReadPasswordTerminal(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "  typed pw \n")
	got, err := std.promptPassword("Enter password: ")
	if err != nil || string(got) != "typed pw" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadPasswordTerminalEmpty(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "   ")
	if _, err := std.promptPassword("Enter password: "); err == nil {
		t.Fatal("empty terminal password must be rejected")
	}
}

func TestReadPasswordTerminalError(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std) // no secrets queued -> EOF
	if _, err := std.promptPassword("Enter password: "); err == nil {
		t.Fatal("expected terminal read error")
	}
}

func TestReadNewPasswordTerminalConfirmMatch(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "s3cret phrase", "s3cret phrase")
	got, err := std.promptNewPassword("Enter password: ", "Confirm password: ")
	if err != nil || string(got) != "s3cret phrase" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadNewPasswordTerminalConfirmMismatch(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "one", "two")
	_, err := std.promptNewPassword("Enter password: ", "Confirm password: ")
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadNewPasswordTerminalConfirmEmpty(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "one", "")
	if _, err := std.promptNewPassword("Enter password: ", "Confirm password: "); err == nil {
		t.Fatal("empty confirmation must fail")
	}
}

func TestReadNewPasswordTerminalFirstEmptyDoesNotPromptAgain(t *testing.T) {
	std := captureStdio(t, "")
	fakeTerminal(std, "", "unused")
	if _, err := std.promptNewPassword("Enter password: ", "Confirm password: "); err == nil {
		t.Fatal("empty first password must fail")
	}
	if strings.Contains(std.err.String(), "Confirm") {
		t.Fatal("must not ask for confirmation after a failed first prompt")
	}
}

func TestReadNewPasswordPipedSkipsConfirmation(t *testing.T) {
	std := captureStdio(t, "only once\n")
	got, err := std.promptNewPassword("Enter password: ", "Confirm password: ")
	if err != nil || string(got) != "only once" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// ----------------------------------------------------------------------------
// Password file, environment variable, key file
// ----------------------------------------------------------------------------

func TestReadPasswordFile(t *testing.T) {
	cases := map[string]struct {
		content string
		want    string
		wantErr bool
	}{
		"plain":            {"hunter2\n", "hunter2", false},
		"no newline":       {"hunter2", "hunter2", false},
		"crlf":             {"hunter2\r\n", "hunter2", false},
		"spaces inside":    {"correct horse battery staple\n", "correct horse battery staple", false},
		"first line only":  {"one\ntwo\n", "one", false},
		"trimmed":          {"  pw \n", "pw", false},
		"empty file":       {"", "", true},
		"blank first line": {"\nsecret\n", "", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			std := captureStdio(t, "")
			path := filepath.Join(t.TempDir(), "pw")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := std.readPasswordFile(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestReadPasswordFileMissing(t *testing.T) {
	std := captureStdio(t, "")
	if _, err := std.readPasswordFile(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "password file") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestReadPasswordFilePermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	tight := filepath.Join(dir, "tight")
	os.WriteFile(loose, []byte("pw\n"), 0644)
	os.WriteFile(tight, []byte("pw\n"), 0600)
	os.Chmod(loose, 0644)

	std := captureStdio(t, "")
	if _, err := std.readPasswordFile(tight); err != nil {
		t.Fatal(err)
	}
	if std.err.Len() != 0 {
		t.Fatalf("0600 file must not warn: %q", std.err.String())
	}
	if pw, err := std.readPasswordFile(loose); err != nil || string(pw) != "pw" {
		t.Fatalf("a loose file still works: %q, %v", pw, err)
	}
	if !strings.Contains(std.err.String(), "accessible by other users") {
		t.Fatalf("expected a permission warning, got %q", std.err.String())
	}
}

func TestReadPasswordEnv(t *testing.T) {
	t.Setenv("BITSEAL_TEST_PW", "from env\n")
	got, err := readPasswordEnv("BITSEAL_TEST_PW")
	if err != nil || string(got) != "from env" {
		t.Fatalf("got %q, %v", got, err)
	}

	t.Setenv("BITSEAL_TEST_EMPTY", "")
	if _, err := readPasswordEnv("BITSEAL_TEST_EMPTY"); err == nil {
		t.Fatal("empty variable must be rejected")
	}
	if _, err := readPasswordEnv("BITSEAL_TEST_DEFINITELY_UNSET"); err == nil || !strings.Contains(err.Error(), "BITSEAL_TEST_DEFINITELY_UNSET") {
		t.Fatalf("unset variable must be rejected by name: %v", err)
	}
}

func TestReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	binary := []byte{0, 1, 2, 0xff, '\n', '\r', 0}
	p := filepath.Join(dir, "kf")
	os.WriteFile(p, binary, 0600)
	got, err := readKeyFile(p)
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("key file must be read verbatim: %v", err)
	}

	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, nil, 0600)
	if _, err := readKeyFile(empty); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := readKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing key file must fail")
	}
	if _, err := readKeyFile(dir); err == nil {
		t.Fatal("a directory is not a key file")
	}
}
