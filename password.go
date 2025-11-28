// ============================================================================
// Secure password input
// ============================================================================

package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// readPassword reads a password from stdin with hidden input
func readPassword() (string, error) {
	fmt.Print("Enter password: ")

	// Get terminal state
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Fallback for non-terminal input (pipes, redirects)
		var pwd string
		_, err := fmt.Scanln(&pwd)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		return pwd, nil
	}

	// Read password with terminal echo disabled
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println() // New line after password input

	password := strings.TrimSpace(string(pwd))
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}
