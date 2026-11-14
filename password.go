// ============================================================================
// Secret input: terminal prompt, piped stdin, password file, environment
// variable and key file
// ============================================================================

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

// Indirections so tests can simulate a terminal.
var (
	stdin              io.Reader = os.Stdin
	stdinIsTerminal              = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	readTerminalSecret           = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
)

// A single buffered reader is shared by all prompts, so a pipe carrying
// several lines (current and new password) is not over-read by the first.
var (
	stdinBuf    *bufio.Reader
	stdinBufSrc io.Reader
)

func stdinLines() *bufio.Reader {
	if stdinBuf == nil || stdinBufSrc != stdin {
		stdinBuf = bufio.NewReader(stdin)
		stdinBufSrc = stdin
	}
	return stdinBuf
}

// readPassword reads a password from stdin with hidden input
func readPassword() ([]byte, error) {
	return promptPassword("Enter password: ")
}

// readNewPassword reads a password for encryption. On a terminal it asks twice
// so a typo cannot produce a file that can never be decrypted.
func readNewPassword() ([]byte, error) {
	return promptNewPassword("Enter password: ", "Confirm password: ")
}

func promptNewPassword(first, second string) ([]byte, error) {
	password, err := promptPassword(first)
	if err != nil {
		return nil, err
	}
	if !stdinIsTerminal() {
		return password, nil
	}

	confirm, err := promptPassword(second)
	if err != nil {
		wipe(password)
		return nil, err
	}
	defer wipe(confirm)
	if !bytes.Equal(password, confirm) {
		wipe(password)
		return nil, fmt.Errorf("passwords do not match")
	}
	return password, nil
}

// promptPassword shows the prompt on stderr so stdout stays clean for data.
func promptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(stderr, prompt)

	if !stdinIsTerminal() {
		// Fallback for non-terminal input (pipes, redirects)
		return readPasswordFrom(stdinLines())
	}

	// Read password with terminal echo disabled
	pwd, err := readTerminalSecret()
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	defer wipe(pwd)
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
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	defer wipe(line)
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
func readPasswordFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read password file: %w", err)
	}
	defer wipe(data)

	if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0077 != 0 {
		fmt.Fprintf(stderr, "Warning: password file %s is accessible by other users (chmod 600 recommended)\n", path)
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
