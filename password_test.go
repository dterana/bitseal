package main

import (
	"errors"
	"io"
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
			if err != nil || got != tc.want {
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

// fakeStdin swaps the terminal/pipe indirections for the duration of a test.
func fakeStdin(t *testing.T, isTerminal bool, piped string, secrets ...string) {
	t.Helper()
	oldStdin, oldIs, oldRead := stdin, stdinIsTerminal, readTerminalSecret
	t.Cleanup(func() { stdin, stdinIsTerminal, readTerminalSecret = oldStdin, oldIs, oldRead })

	stdin = strings.NewReader(piped)
	stdinIsTerminal = func() bool { return isTerminal }
	i := 0
	readTerminalSecret = func() ([]byte, error) {
		if i >= len(secrets) {
			return nil, io.EOF
		}
		s := secrets[i]
		i++
		return []byte(s), nil
	}
}

func TestReadPasswordPiped(t *testing.T) {
	fakeStdin(t, false, "hello world\n")
	got, err := readPassword()
	if err != nil || got != "hello world" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadPasswordTerminal(t *testing.T) {
	fakeStdin(t, true, "", "  typed pw \n")
	got, err := readPassword()
	if err != nil || got != "typed pw" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadPasswordTerminalEmpty(t *testing.T) {
	fakeStdin(t, true, "", "   ")
	if _, err := readPassword(); err == nil {
		t.Fatal("empty terminal password must be rejected")
	}
}

func TestReadPasswordTerminalError(t *testing.T) {
	fakeStdin(t, true, "") // no secrets queued -> EOF
	if _, err := readPassword(); err == nil {
		t.Fatal("expected terminal read error")
	}
}

func TestReadNewPasswordTerminalConfirmMatch(t *testing.T) {
	fakeStdin(t, true, "", "s3cret phrase", "s3cret phrase")
	got, err := readNewPassword()
	if err != nil || got != "s3cret phrase" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestReadNewPasswordTerminalConfirmMismatch(t *testing.T) {
	fakeStdin(t, true, "", "one", "two")
	_, err := readNewPassword()
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadNewPasswordTerminalConfirmEmpty(t *testing.T) {
	fakeStdin(t, true, "", "one", "")
	if _, err := readNewPassword(); err == nil {
		t.Fatal("empty confirmation must fail")
	}
}

func TestReadNewPasswordTerminalFirstEmptyDoesNotPromptAgain(t *testing.T) {
	fakeStdin(t, true, "", "", "unused")
	if _, err := readNewPassword(); err == nil {
		t.Fatal("empty first password must fail")
	}
}

func TestReadNewPasswordPipedSkipsConfirmation(t *testing.T) {
	// a pipe carries one line: asking twice would consume nothing and fail
	fakeStdin(t, false, "only once\n")
	got, err := readNewPassword()
	if err != nil || got != "only once" {
		t.Fatalf("got %q, %v", got, err)
	}
}
