// Package cli implements the casemate command line: commands, flags and
// secret input, on top of the seal package.
//
// Everything that touches the process (streams, terminal detection, the
// cipher manager) is a field of App, so the commands are testable without
// global state.
package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/dterana/casemate/internal/seal"
)

// App is one invocation environment of the CLI.
type App struct {
	// Data goes to Stdout; prompts, progress and errors go to Stderr so
	// `casemate decrypt -out - | ...` stays clean.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	StdinIsTerminal    func() bool
	StdoutIsTerminal   func() bool
	ReadTerminalSecret func() ([]byte, error)

	// NewManager builds the manager used by commands. Its streams are wired
	// to the App's before use.
	NewManager func() *seal.Manager

	Version string
	Build   string

	// One buffered reader is shared by all prompts, so a pipe carrying
	// several lines (current and new password) is not over-read by the first.
	stdinBuf *bufio.Reader
}

// New returns an App wired to the real process.
func New(version, build string) *App {
	return &App{
		Stdin:              os.Stdin,
		Stdout:             os.Stdout,
		Stderr:             os.Stderr,
		StdinIsTerminal:    func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		StdoutIsTerminal:   func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		ReadTerminalSecret: func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) },
		NewManager:         seal.NewManager,
		Version:            version,
		Build:              build,
	}
}

func (a *App) manager() *seal.Manager {
	m := a.NewManager()
	m.In, m.Out, m.OutIsTerminal = a.Stdin, a.Stdout, a.StdoutIsTerminal
	return m
}

var (
	errUsage    = errors.New("usage error")
	errReported = errors.New("error already reported")
)

const usageText = `Casemate - File Encryption CLI Tool
Version: v%s

Usage:
  casemate encrypt [flags] [path...]   Encrypt files (writes <file>.enc) or directories
                                      (writes <dir>.tar.enc)
  casemate decrypt [flags] [file...]   Decrypt files (strips .enc); with -extract, unpack
                                      a directory archive into a new directory
  casemate rekey   [flags] [file...]   Re-encrypt files in place with the current
                                      format, optionally with a new password or key file
  casemate info    [flags] [file...]   Show a file's format without decrypting it (-json for JSON)
  casemate keygen  -out <path>         Create a random key file (use it with -keyfile)
  casemate version                     Show version information

Common flags (put them before the file names):
  -file <path>            Input file, repeatable; - reads stdin
  -out <path>             Output file (single input only); - writes stdout
  -password-file <path>   Read the password from the first line of a file
  -password-env <name>    Read the password from an environment variable
  -password-fd <n>        Read the password from a file descriptor (3 or higher)
  -keyfile <path>         Use a key file as a second factor
  -strict                 Refuse a password file others can read and a new
                          password under 12 characters (warnings become errors)

Run 'casemate <command> -h' to list all flags of a command.
`

// Run executes the CLI with the given arguments (without the program name)
// and returns the process exit code: 0 success, 1 an operation failed,
// 2 invalid flags.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(a.Stderr, usageText, a.Version)
		return 1
	}

	var err error
	switch args[0] {
	case "encrypt":
		err = a.cmdEncrypt(args[1:])
	case "decrypt":
		err = a.cmdDecrypt(args[1:])
	case "rekey":
		err = a.cmdRekey(args[1:])
	case "info":
		err = a.cmdInfo(args[1:])
	case "keygen":
		err = a.cmdKeygen(args[1:])
	case "version", "-version", "--version":
		fmt.Fprintf(a.Stdout, "Casemate v%s (build: %s)\n", a.Version, a.Build)
	case "help", "-h", "--help":
		fmt.Fprintf(a.Stdout, usageText, a.Version)
	default:
		fmt.Fprintf(a.Stderr, "Unknown command: %s\nRun 'casemate help' for usage.\n", args[0])
		return 1
	}

	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		return 2
	case errors.Is(err, errReported):
		return 1
	}
	fmt.Fprintf(a.Stderr, "Error: %v\n", err)
	return 1
}

func inLabel(path string) string {
	if path == seal.StdioPath {
		return "stdin"
	}
	return path
}

func outLabel(path string) string {
	if path == seal.StdioPath {
		return "stdout"
	}
	return path
}

func (a *App) reportFailure(prefix, file string, err error) {
	fmt.Fprintf(a.Stderr, "%s: %s: %v\n", prefix, inLabel(file), err)
}

func (a *App) summarize(failed, total int) error {
	if failed == 0 {
		return nil
	}
	if total > 1 {
		fmt.Fprintf(a.Stderr, "%d of %d files failed\n", failed, total)
	}
	return errReported
}
