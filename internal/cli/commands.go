package cli

import (
	"fmt"
	"strings"

	"github.com/dterana/bitseal/internal/seal"
)

func (a *App) cmdEncrypt(args []string) error {
	fs := a.newFlagSet("encrypt")
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

	secret, err := a.resolveSecret(sf, "Enter password: ", true, containsStdin(files))
	if err != nil {
		return err
	}
	defer secret.Wipe()

	manager := a.manager()
	failed := 0
	for _, f := range files {
		if err := manager.EncryptFile(f, in.out, secret); err != nil {
			a.reportFailure("Encryption error", f, err)
			failed++
			continue
		}
		fmt.Fprintf(a.Stderr, "✓ Encrypted %s -> %s\n", inLabel(f), outLabel(seal.ResolveEncryptOut(f, in.out)))
	}
	return a.summarize(failed, len(files))
}

func (a *App) cmdDecrypt(args []string) error {
	fs := a.newFlagSet("decrypt")
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

	secret, err := a.resolveSecret(sf, "Enter password: ", false, containsStdin(files))
	if err != nil {
		return err
	}
	defer secret.Wipe()

	manager := a.manager()
	failed := 0
	for _, f := range files {
		if err := manager.DecryptFile(f, in.out, secret); err != nil {
			a.reportFailure("Decryption error", f, err)
			failed++
			continue
		}
		dest, _ := seal.ResolveDecryptOut(f, in.out)
		fmt.Fprintf(a.Stderr, "✓ Decrypted %s -> %s\n", inLabel(f), outLabel(dest))
	}
	return a.summarize(failed, len(files))
}

func (a *App) cmdRekey(args []string) error {
	fs := a.newFlagSet("rekey")
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
	old, err := a.resolveSecret(sf, prompt, false, false)
	if err != nil {
		return err
	}
	defer old.Wipe()

	next, err := a.newSecret(rk, old)
	if err != nil {
		return err
	}
	defer next.Wipe()

	manager := a.manager()
	failed := 0
	for _, f := range files {
		if err := manager.RekeyFile(f, in.out, old, next); err != nil {
			a.reportFailure("Rekey error", f, err)
			failed++
			continue
		}
		dest := in.out
		if dest == "" {
			dest = f
		}
		fmt.Fprintf(a.Stderr, "✓ Re-encrypted %s -> %s\n", f, dest)
	}
	return a.summarize(failed, len(files))
}

func (a *App) cmdInfo(args []string) error {
	fs := a.newFlagSet("info")
	var in fileArgs
	in.register(fs, false)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	files, err := in.inputs(fs)
	if err != nil {
		return err
	}

	manager := a.manager()
	failed := 0
	for i, f := range files {
		info, err := manager.InspectFile(f)
		if err != nil {
			a.reportFailure("Info error", f, err)
			failed++
			continue
		}
		if i > 0 {
			fmt.Fprintln(a.Stdout)
		}
		fmt.Fprint(a.Stdout, formatInfo(f, info))
	}
	return a.summarize(failed, len(files))
}

func formatInfo(name string, info seal.FileInfo) string {
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
