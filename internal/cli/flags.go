package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/dterana/casemate/internal/seal"
)

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
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

func (f *fileArgs) register(fs *flag.FlagSet, withOut bool) {
	fs.Var(&f.files, "file", "input file, repeatable (- reads stdin)")
	if withOut {
		fs.StringVar(&f.out, "out", "", "output file, single input only (- writes stdout)")
	}
}

// inputs merges -file values with positional arguments and validates them.
func (f *fileArgs) inputs(fs *flag.FlagSet) ([]string, error) {
	files := append(append([]string(nil), f.files...), fs.Args()...)
	switch {
	case len(files) == 0:
		return nil, fmt.Errorf("no input file given: use -file <path> or pass file names as arguments")
	case len(files) > 1 && f.out != "":
		return nil, fmt.Errorf("-out can only be used with a single input file")
	case len(files) > 1 && containsStdin(files):
		return nil, fmt.Errorf("stdin (-) cannot be combined with other input files")
	}
	return files, nil
}

func containsStdin(files []string) bool {
	for _, f := range files {
		if f == seal.StdioPath {
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
	passwordFD   int
	keyFile      string
	strict       bool
}

// noFD is the default of the -password-fd flags: no descriptor given.
const noFD = -1

func (f *secretFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.passwordFile, "password-file", "", "read the password from the first line of this file")
	fs.StringVar(&f.passwordEnv, "password-env", "", "read the password from this environment variable")
	fs.IntVar(&f.passwordFD, "password-fd", noFD, "read the password from the first line of this file descriptor")
	fs.StringVar(&f.keyFile, "keyfile", "", "use this key file as a second factor")
	fs.BoolVar(&f.strict, "strict", false, "refuse a password file others can read and a new password under 12 characters")
}

func (a *App) readPassword(f secretFlags, prompt string, confirm, stdinBusy bool) ([]byte, error) {
	if countSet(f.passwordFile != "", f.passwordEnv != "", f.passwordFD != noFD) > 1 {
		return nil, fmt.Errorf("use only one of -password-file, -password-env and -password-fd")
	}
	switch {
	case f.passwordFile != "":
		return a.readPasswordFile(f.passwordFile, f.strict)
	case f.passwordEnv != "":
		return readPasswordEnv(f.passwordEnv)
	case f.passwordFD != noFD:
		return readPasswordFD(f.passwordFD)
	case stdinBusy:
		return nil, fmt.Errorf("cannot read the password from stdin while the input is stdin; use -password-file or -password-env")
	case confirm:
		return a.promptNewPassword(prompt, "Confirm password: ")
	}
	return a.promptPassword(prompt)
}

func (a *App) resolveSecret(f secretFlags, prompt string, confirm, stdinBusy bool) (seal.Secret, error) {
	pw, err := a.readPassword(f, prompt, confirm, stdinBusy)
	if err != nil {
		return seal.Secret{}, err
	}
	if confirm {
		if err := a.checkLength(pw, f.strict); err != nil {
			seal.Wipe(pw)
			return seal.Secret{}, err
		}
	}
	secret := seal.Secret{Password: pw}
	if f.keyFile != "" {
		kf, err := readKeyFile(f.keyFile)
		if err != nil {
			seal.Wipe(pw)
			return seal.Secret{}, err
		}
		secret.KeyFile = kf
	}
	return secret, nil
}

// rekeyFlags describe how the secret changes during a rekey. By default the
// same password and key file are kept and only the file format is upgraded.
type rekeyFlags struct {
	changePassword  bool
	newPasswordFile string
	newPasswordEnv  string
	newPasswordFD   int
	newKeyFile      string
	noKeyFile       bool
	recursive       bool
	dryRun          bool
}

func (r *rekeyFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&r.changePassword, "change-password", false, "prompt for a new password")
	fs.StringVar(&r.newPasswordFile, "new-password-file", "", "read the new password from the first line of this file")
	fs.StringVar(&r.newPasswordEnv, "new-password-env", "", "read the new password from this environment variable")
	fs.IntVar(&r.newPasswordFD, "new-password-fd", noFD, "read the new password from the first line of this file descriptor")
	fs.StringVar(&r.newKeyFile, "new-keyfile", "", "set or replace the key file")
	fs.BoolVar(&r.noKeyFile, "no-keyfile", false, "remove the key file requirement")
	fs.BoolVar(&r.recursive, "recursive", false, "rekey every .enc file under the directories given (symlinks are skipped)")
	fs.BoolVar(&r.dryRun, "dry-run", false, "list the files that would be rekeyed and their format, without a password and without writing")
}

func (r rekeyFlags) changesPassword() bool {
	return r.changePassword || r.newPasswordFile != "" || r.newPasswordEnv != "" || r.newPasswordFD != noFD
}

func (a *App) newSecret(r rekeyFlags, old seal.Secret, strict bool) (seal.Secret, error) {
	if countSet(r.newPasswordFile != "", r.newPasswordEnv != "", r.newPasswordFD != noFD) > 1 {
		return seal.Secret{}, fmt.Errorf("use only one of -new-password-file, -new-password-env and -new-password-fd")
	}
	if r.noKeyFile && r.newKeyFile != "" {
		return seal.Secret{}, fmt.Errorf("-no-keyfile and -new-keyfile cannot be combined")
	}

	next := seal.Secret{Password: old.Password, KeyFile: old.KeyFile}
	var err error
	switch {
	case r.newPasswordFile != "":
		next.Password, err = a.readPasswordFile(r.newPasswordFile, strict)
	case r.newPasswordEnv != "":
		next.Password, err = readPasswordEnv(r.newPasswordEnv)
	case r.newPasswordFD != noFD:
		next.Password, err = readPasswordFD(r.newPasswordFD)
	case r.changePassword:
		next.Password, err = a.promptNewPassword("New password: ", "Confirm new password: ")
	}
	if err != nil {
		return seal.Secret{}, err
	}

	if r.changesPassword() {
		if err := a.checkLength(next.Password, strict); err != nil {
			seal.Wipe(next.Password)
			return seal.Secret{}, err
		}
	}

	switch {
	case r.noKeyFile:
		next.KeyFile = nil
	case r.newKeyFile != "":
		kf, err := readKeyFile(r.newKeyFile)
		if err != nil {
			if r.changesPassword() {
				seal.Wipe(next.Password)
			}
			return seal.Secret{}, err
		}
		next.KeyFile = kf
	}
	return next, nil
}

func countSet(flags ...bool) int {
	n := 0
	for _, set := range flags {
		if set {
			n++
		}
	}
	return n
}
