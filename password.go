// ============================================================================
// Secure password input
// ============================================================================

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Indirections so tests can simulate a terminal.
var (
	stdin              io.Reader = os.Stdin
	stdinIsTerminal              = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	readTerminalSecret           = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
)

// readPassword reads a password from stdin with hidden input
func readPassword() (string, error) {
	return readPasswordPrompt("Enter password: ")
}

// readNewPassword reads a password for encryption. On a terminal it asks twice
// so a typo cannot produce a file that can never be decrypted.
func readNewPassword() (string, error) {
	password, err := readPasswordPrompt("Enter password: ")
	if err != nil {
		return "", err
	}
	if !stdinIsTerminal() {
		return password, nil
	}

	confirm, err := readPasswordPrompt("Confirm password: ")
	if err != nil {
		return "", err
	}
	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return password, nil
}

func readPasswordPrompt(prompt string) (string, error) {
	fmt.Print(prompt)

	if !stdinIsTerminal() {
		// Fallback for non-terminal input (pipes, redirects)
		return readPasswordLine(stdin)
	}

	// Read password with terminal echo disabled
	pwd, err := readTerminalSecret()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println() // New line after password input

	return cleanPassword(string(pwd))
}

// readPasswordLine reads the first line of r as the password. Spaces inside
// the password are preserved; surrounding whitespace is trimmed, matching
// the terminal behaviour.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return cleanPassword(line)
}

func cleanPassword(s string) (string, error) {
	password := strings.TrimSpace(s)
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}
