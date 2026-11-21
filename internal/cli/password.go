// ============================================================================
// Secret input: terminal prompt, piped stdin, password file, environment
// variable and key file
// ============================================================================

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unicode/utf8"

	"github.com/dterana/casemate/internal/seal"
)

func (a *App) stdinLines() *bufio.Reader {
	if a.stdinBuf == nil {
		a.stdinBuf = bufio.NewReader(a.Stdin)
	}
	return a.stdinBuf
}

// promptNewPassword reads a password for encryption. On a terminal it asks
// twice so a typo cannot produce a file that can never be decrypted.
func (a *App) promptNewPassword(first, second string) ([]byte, error) {
	password, err := a.promptPassword(first)
	if err != nil {
		return nil, err
	}
	if !a.StdinIsTerminal() {
		return password, nil
	}

	confirm, err := a.promptPassword(second)
	if err != nil {
		seal.Wipe(password)
		return nil, err
	}
	defer seal.Wipe(confirm)
	if !bytes.Equal(password, confirm) {
		seal.Wipe(password)
		return nil, fmt.Errorf("passwords do not match")
	}
	return password, nil
}

// promptPassword shows the prompt on stderr so stdout stays clean for data.
func (a *App) promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(a.Stderr, prompt)

	if !a.StdinIsTerminal() {
		// Fallback for non-terminal input (pipes, redirects)
		return readPasswordFrom(a.stdinLines())
	}

	// Read password with terminal echo disabled
	pwd, err := a.ReadTerminalSecret()
	fmt.Fprintln(a.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	defer seal.Wipe(pwd)
	return cleanPassword(pwd)
}

// readPasswordLine reads the first line of r as the password. Spaces inside
// the password are preserved; surrounding whitespace is trimmed, matching
// the terminal behaviour.
func readPasswordLine(r io.Reader) ([]byte, error) {
	return readPasswordFrom(bufio.NewReader(r))
}

func readPasswordFrom(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	defer seal.Wipe(line)
	return cleanPassword(line)
}

// cleanPassword trims surrounding whitespace and returns a fresh copy, so the
// caller's buffer can be wiped independently.
func cleanPassword(b []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	return append([]byte(nil), trimmed...), nil
}

// readPasswordFile reads the first line of a file as the password.
// With strict, a file that other users can read is an error, not a warning.
func (a *App) readPasswordFile(path string, strict bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read password file: %w", err)
	}
	defer seal.Wipe(data)

	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0077 != 0 {
		if strict {
			return nil, fmt.Errorf("password file %s is accessible by other users (-strict); run chmod 600 on it", path)
		}
		fmt.Fprintf(a.Stderr, "Warning: password file %s is accessible by other users (chmod 600 recommended)\n", path)
	}

	line := data
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		line = data[:i]
	}
	pw, err := cleanPassword(line)
	if err != nil {
		return nil, fmt.Errorf("password file %s is empty", path)
	}
	return pw, nil
}

// readPasswordEnv reads the password from an environment variable.
func readPasswordEnv(name string) ([]byte, error) {
	pw, err := cleanPassword([]byte(os.Getenv(name)))
	if err != nil {
		return nil, fmt.Errorf("environment variable %s is not set or empty", name)
	}
	return pw, nil
}

// readKeyFile reads a key file used as a second factor.
func readKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("key file %s is empty", path)
	}
	return data, nil
}

// minPasswordLength is the length below which Casemate warns, or refuses
// with -strict. Without -strict it is advice, not a rule.
const minPasswordLength = 12

// checkLength tells the user a new password is short. Argon2id slows guessing
// but cannot save a guessable password. With strict, a short password is an error.
func (a *App) checkLength(pw []byte, strict bool) error {
	n := utf8.RuneCount(pw)
	if n >= minPasswordLength {
		return nil
	}
	if strict {
		return fmt.Errorf("the password has only %d characters and -strict requires %d or more; use a longer passphrase or add -keyfile", n, minPasswordLength)
	}
	fmt.Fprintf(a.Stderr, "Warning: the password has only %d characters; use a passphrase of %d or more, or add -keyfile\n", n, minPasswordLength)
	return nil
}

// readPasswordFD reads the first line of an inherited file descriptor as the
// password, for callers that pass secrets over a pipe (for example
// `casemate decrypt -password-fd 3 f.enc 3< <(pass show casemate)`).
func readPasswordFD(fd int) ([]byte, error) {
	if fd <= 2 {
		return nil, fmt.Errorf("-password-fd must be 3 or higher (0, 1 and 2 are stdin, stdout and stderr)")
	}
	f, err := openFD(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to read password from descriptor %d: %w", fd, err)
	}
	defer func() { _ = f.Close() }()
	pw, err := readPasswordLine(f)
	if err != nil {
		return nil, fmt.Errorf("descriptor %d: %w", fd, err)
	}
	return pw, nil
}
