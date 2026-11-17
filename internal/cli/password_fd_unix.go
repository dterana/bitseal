//go:build unix

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// openFD wraps a duplicate of fd, so closing the returned file leaves the
// caller's descriptor alone.
func openFD(fd int) (*os.File, error) {
	dup, err := syscall.Dup(fd)
	if err != nil {
		return nil, fmt.Errorf("not an open descriptor: %w", err)
	}
	return os.NewFile(uintptr(dup), fmt.Sprintf("fd%d", fd)), nil
}
