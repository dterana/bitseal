// Command bitseal encrypts and decrypts files with versioned, future-proof
// formats. See the README for usage and docs/format.md for the file formats.
package main

import (
	"os"

	"github.com/dterana/bitseal/internal/cli"
	"github.com/dterana/bitseal/internal/seal"
)

func main() {
	seal.InstallSignalCleanup()
	os.Exit(cli.New(Version, buildString()).Run(os.Args[1:]))
}
