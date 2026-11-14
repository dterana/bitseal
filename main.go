package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Process streams. Data goes to stdout; prompts, progress and errors go to
// stderr so `bitseal decrypt -out - | ...` stays clean.
var (
	stdout           io.Writer = os.Stdout
	stderr           io.Writer = os.Stderr
	stdoutIsTerminal           = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
)

// newManager builds the manager used by commands (overridable in tests).
var newManager = NewCipherManager

var (
	errUsage    = errors.New("usage error")
	errReported = errors.New("error already reported")
)

const usageText = `Bitseal - File Encryption CLI Tool
Version: v%s

Usage:
  bitseal encrypt [flags] [file...]   Encrypt files (writes <file>.enc)
  bitseal decrypt [flags] [file...]   Decrypt files (strips .enc)
  bitseal rekey   [flags] [file...]   Re-encrypt files in place with the current
                                      format, optionally with a new password or key file
  bitseal info    [file...]           Show a file's format without decrypting it
  bitseal version                     Show version information

Common flags (put them before the file names):
  -file <path>            Input file, repeatable; - reads stdin
  -out <path>             Output file (single input only); - writes stdout
  -password-file <path>   Read the password from the first line of a file
  -password-env <name>    Read the password from an environment variable
  -keyfile <path>         Use a key file as a second factor

Run 'bitseal <command> -h' to list all flags of a command.
`

func main() {
	installSignalCleanup()
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usageText, Version)
		return 1
	}

	var err error
	switch args[0] {
	case "encrypt":
		err = cmdEncrypt(args[1:])
	case "decrypt":
		err = cmdDecrypt(args[1:])
	case "rekey":
		err = cmdRekey(args[1:])
	case "info":
		err = cmdInfo(args[1:])
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "Bitseal v%s (build: %s)\n", Version, buildString())
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usageText, Version)
	default:
		fmt.Fprintf(stderr, "Unknown command: %s\nRun 'bitseal help' for usage.\n", args[0])
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
	fmt.Fprintf(stderr, "Error: %v\n", err)
	return 1
}

// ----------------------------------------------------------------------------
// Flag helpers
// ----------------------------------------------------------------------------

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	return nil
}

// fileArgs are the -file/-out flags shared by the file commands.
type fileArgs struct {
	files stringList
	out   string
}

func (a *fileArgs) register(fs *flag.FlagSet, withOut bool) {
	fs.Var(&a.files, "file", "input file, repeatable (- reads stdin)")
	if withOut {
		fs.StringVar(&a.out, "out", "", "output file, single input only (- writes stdout)")
	}
}

// inputs merges -file values with positional arguments and validates them.
func (a *fileArgs) inputs(fs *flag.FlagSet) ([]string, error) {
	files := append(append([]string(nil), a.files...), fs.Args()...)
	switch {
	case len(files) == 0:
		return nil, fmt.Errorf("no input file given: use -file <path> or pass file names as arguments")
	case len(files) > 1 && a.out != "":
		return nil, fmt.Errorf("-out can only be used with a single input file")
	case len(files) > 1 && containsStdin(files):
		return nil, fmt.Errorf("stdin (-) cannot be combined with other input files")
	}
	return files, nil
}

func containsStdin(files []string) bool {
	for _, f := range files {
		if f == stdioPath {
			return true
		}
	}
	return false
}

// secretFlags select where the password and key file come from. Without
// -password-file or -password-env the password is prompted (or read from a pipe).
type secretFlags struct {
	passwordFile string
	passwordEnv  string
	keyFile      string
}

func (f *secretFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.passwordFile, "password-file", "", "read the password from the first line of this file")
	fs.StringVar(&f.passwordEnv, "password-env", "", "read the password from this environment variable")
	fs.StringVar(&f.keyFile, "keyfile", "", "use this key file as a second factor")
}

func (f secretFlags) readPassword(prompt string, confirm, stdinBusy bool) ([]byte, error) {
	if f.passwordFile != "" && f.passwordEnv != "" {
		return nil, fmt.Errorf("use only one of -password-file and -password-env")
	}
	switch {
	case f.passwordFile != "":
		return readPasswordFile(f.passwordFile)
	case f.passwordEnv != "":
		return readPasswordEnv(f.passwordEnv)
	case stdinBusy:
		return nil, fmt.Errorf("cannot read the password from stdin while the input is stdin; use -password-file or -password-env")
	case confirm:
		return promptNewPassword(prompt, "Confirm password: ")
	}
	return promptPassword(prompt)
}

func (f secretFlags) resolve(prompt string, confirm, stdinBusy bool) (Secret, error) {
	pw, err := f.readPassword(prompt, confirm, stdinBusy)
	if err != nil {
		return Secret{}, err
	}
	secret := Secret{Password: pw}
	if f.keyFile != "" {
		kf, err := readKeyFile(f.keyFile)
		if err != nil {
			wipe(pw)
			return Secret{}, err
		}
		secret.KeyFile = kf
	}
	return secret, nil
}

func inLabel(path string) string {
	if path == stdioPath {
		return "stdin"
	}
	return path
}

func outLabel(path string) string {
	if path == stdioPath {
		return "stdout"
	}
	return path
}

func reportFailure(prefix, file string, err error) {
	fmt.Fprintf(stderr, "%s: %s: %v\n", prefix, inLabel(file), err)
}

func summarize(failed, total int) error {
	if failed == 0 {
		return nil
	}
	if total > 1 {
		fmt.Fprintf(stderr, "%d of %d files failed\n", failed, total)
	}
	return errReported
}

// ----------------------------------------------------------------------------
// Commands
// ----------------------------------------------------------------------------

func cmdEncrypt(args []string) error {
	fs := newFlagSet("encrypt")
	var in fileArgs
	var sf secretFlags
	in.register(fs, true)
	sf.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	files, err := in.inputs(fs)
	if err != nil {
		return err
	}

	secret, err := sf.resolve("Enter password: ", true, containsStdin(files))
	if err != nil {
		return err
	}
	defer secret.Wipe()

	manager := newManager()
	failed := 0
	for _, f := range files {
		if err := manager.EncryptFile(f, in.out, secret); err != nil {
			reportFailure("Encryption error", f, err)
			failed++
			continue
		}
		fmt.Fprintf(stderr, "✓ Encrypted %s -> %s\n", inLabel(f), outLabel(resolveEncryptOut(f, in.out)))
	}
	return summarize(failed, len(files))
}

func cmdDecrypt(args []string) error {
	fs := newFlagSet("decrypt")
	var in fileArgs
	var sf secretFlags
	in.register(fs, true)
	sf.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	files, err := in.inputs(fs)
	if err != nil {
		return err
	}

	secret, err := sf.resolve("Enter password: ", false, containsStdin(files))
	if err != nil {
		return err
	}
	defer secret.Wipe()

	manager := newManager()
	failed := 0
	for _, f := range files {
		if err := manager.DecryptFile(f, in.out, secret); err != nil {
			reportFailure("Decryption error", f, err)
			failed++
			continue
		}
		dest, _ := resolveDecryptOut(f, in.out)
		fmt.Fprintf(stderr, "✓ Decrypted %s -> %s\n", inLabel(f), outLabel(dest))
	}
	return summarize(failed, len(files))
}

// rekeyFlags describe how the secret changes during a rekey. By default the
// same password and key file are kept and only the file format is upgraded.
type rekeyFlags struct {
	changePassword  bool
	newPasswordFile string
	newPasswordEnv  string
	newKeyFile      string
	noKeyFile       bool
}

func (r *rekeyFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&r.changePassword, "change-password", false, "prompt for a new password")
	fs.StringVar(&r.newPasswordFile, "new-password-file", "", "read the new password from the first line of this file")
	fs.StringVar(&r.newPasswordEnv, "new-password-env", "", "read the new password from this environment variable")
	fs.StringVar(&r.newKeyFile, "new-keyfile", "", "set or replace the key file")
	fs.BoolVar(&r.noKeyFile, "no-keyfile", false, "remove the key file requirement")
}

func (r rekeyFlags) changesPassword() bool {
	return r.changePassword || r.newPasswordFile != "" || r.newPasswordEnv != ""
}

func (r rekeyFlags) newSecret(old Secret) (Secret, error) {
	if r.newPasswordFile != "" && r.newPasswordEnv != "" {
		return Secret{}, fmt.Errorf("use only one of -new-password-file and -new-password-env")
	}
	if r.noKeyFile && r.newKeyFile != "" {
		return Secret{}, fmt.Errorf("-no-keyfile and -new-keyfile cannot be combined")
	}

	next := Secret{Password: old.Password, KeyFile: old.KeyFile}
	var err error
	switch {
	case r.newPasswordFile != "":
		next.Password, err = readPasswordFile(r.newPasswordFile)
	case r.newPasswordEnv != "":
		next.Password, err = readPasswordEnv(r.newPasswordEnv)
	case r.changePassword:
		next.Password, err = promptNewPassword("New password: ", "Confirm new password: ")
	}
	if err != nil {
		return Secret{}, err
	}

	switch {
	case r.noKeyFile:
		next.KeyFile = nil
	case r.newKeyFile != "":
		kf, err := readKeyFile(r.newKeyFile)
		if err != nil {
			if r.changesPassword() {
				wipe(next.Password)
			}
			return Secret{}, err
		}
		next.KeyFile = kf
	}
	return next, nil
}

func cmdRekey(args []string) error {
	fs := newFlagSet("rekey")
	var in fileArgs
	var sf secretFlags
	var rk rekeyFlags
	in.register(fs, true)
	sf.register(fs)
	rk.register(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	files, err := in.inputs(fs)
	if err != nil {
		return err
	}
	if containsStdin(files) {
		return fmt.Errorf("rekey works on files only, not stdin")
	}

	prompt := "Enter password: "
	if rk.changePassword {
		prompt = "Current password: "
	}
	old, err := sf.resolve(prompt, false, false)
	if err != nil {
		return err
	}
	defer old.Wipe()

	next, err := rk.newSecret(old)
	if err != nil {
		return err
	}
	defer next.Wipe()

	manager := newManager()
	failed := 0
	for _, f := range files {
		if err := manager.RekeyFile(f, in.out, old, next); err != nil {
			reportFailure("Rekey error", f, err)
			failed++
			continue
		}
		dest := in.out
		if dest == "" {
			dest = f
		}
		fmt.Fprintf(stderr, "✓ Re-encrypted %s -> %s\n", f, dest)
	}
	return summarize(failed, len(files))
}

func cmdInfo(args []string) error {
	fs := newFlagSet("info")
	var in fileArgs
	in.register(fs, false)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	files, err := in.inputs(fs)
	if err != nil {
		return err
	}

	manager := newManager()
	failed := 0
	for i, f := range files {
		info, err := manager.InspectFile(f)
		if err != nil {
			reportFailure("Info error", f, err)
			failed++
			continue
		}
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprint(stdout, formatInfo(f, info))
	}
	return summarize(failed, len(files))
}

func formatInfo(name string, info FileInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "File:      %s\n", inLabel(name))
	fmt.Fprintf(&b, "Version:   %d\n", info.Version)

	cipher := info.Cipher
	if info.ChunkSize > 0 {
		cipher = fmt.Sprintf("%s, %d KiB chunks", cipher, info.ChunkSize/1024)
		if info.ChunkSize < 1024 {
			cipher = fmt.Sprintf("%s, %d byte chunks", info.Cipher, info.ChunkSize)
		}
	}
	fmt.Fprintf(&b, "Cipher:    %s\n", cipher)
	fmt.Fprintf(&b, "KDF:       %s\n", info.KDF)

	switch {
	case info.Legacy:
		fmt.Fprintf(&b, "Key file:  not supported\n")
		fmt.Fprintf(&b, "Status:    legacy format, upgrade with: bitseal rekey %s\n", inLabel(name))
	case info.KeyFile:
		fmt.Fprintf(&b, "Key file:  required\n")
	default:
		fmt.Fprintf(&b, "Key file:  not required\n")
	}
	return b.String()
}
