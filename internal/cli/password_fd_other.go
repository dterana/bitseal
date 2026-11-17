//go:build !unix

package cli

import (
	"errors"
	"os"
)

func openFD(int) (*os.File, error) {
	return nil, errors.New("-password-fd is not supported on this platform")
}
