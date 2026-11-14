package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestManagerRegistersAllVersions(t *testing.T) {
	m := NewCipherManager()
	for _, v := range []byte{1, 2} {
		c, err := m.getCipher(v)
		if err != nil {
			t.Fatalf("version %d: %v", v, err)
		}
		if c.Version() != v {
			t.Fatalf("version %d mapped to cipher %d", v, c.Version())
		}
	}
	if _, err := m.getCipher(CurrentVersion); err != nil {
		t.Fatalf("CurrentVersion not registered: %v", err)
	}
}

func TestManagerUnsupportedVersions(t *testing.T) {
	m := NewCipherManager()
	for _, v := range []byte{0, 3, 99, 255} {
		if _, err := m.getCipher(v); err == nil {
			t.Fatalf("version %d should be unsupported", v)
		}
	}
}

func TestEncryptFileDefaultsToCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := NewCipherManager().EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, in+".enc")[0]; got != CurrentVersion {
		t.Fatalf("version = %d, want %d", got, CurrentVersion)
	}
}

func TestEncryptFileKeepsInput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := NewCipherManager().EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, in), []byte("hello")) {
		t.Fatal("input file must be left untouched")
	}
}

func TestEncryptFileCustomOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	out := filepath.Join(dir, "custom.bin")
	writeFile(t, in, []byte("hello"))
	if err := NewCipherManager().EncryptFile(in, out, "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal("custom output not written")
	}
	if _, err := os.Stat(in + ".enc"); err == nil {
		t.Fatal("default .enc output must not be written when -out is given")
	}
}

func TestEncryptFileOutputPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	m := NewCipherManager()
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "out.txt"), "pw"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{in + ".enc", filepath.Join(dir, "out.txt")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %v, want 0600", p, fi.Mode().Perm())
		}
	}
}

func TestEncryptFileOverwritesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("new"))
	writeFile(t, in+".enc", []byte("stale"))
	m := NewCipherManager()
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "o")
	if err := m.DecryptFile(in+".enc", out, "pw"); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, out)) != "new" {
		t.Fatal("stale output was not replaced")
	}
}

func TestEncryptFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	t.Run("missing input", func(t *testing.T) {
		if err := m.EncryptFile(filepath.Join(dir, "nope"), "", "pw"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("input is a directory", func(t *testing.T) {
		if err := m.EncryptFile(dir, "", "pw"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty password", func(t *testing.T) {
		in := filepath.Join(dir, "a.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, "", ""); err == nil {
			t.Fatal("expected error")
		}
		if _, err := os.Stat(in + ".enc"); err == nil {
			t.Fatal("no output may be written when encryption fails")
		}
	})
	t.Run("unwritable output dir", func(t *testing.T) {
		in := filepath.Join(dir, "b.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, filepath.Join(dir, "missing", "out.enc"), "pw"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestDecryptFileDefaultOutputStripsEnc(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "notes.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	os.Remove(in)
	if err := m.DecryptFile(in+".enc", "", "pw"); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("default decrypt output should be the name without .enc")
	}
}

func TestDecryptFileNonEncExtensionRequiresOut(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	enc, _ := NewCipherV2().Encrypt([]byte("hello"), []byte("pw"))
	in := filepath.Join(dir, "blob.bin")
	writeFile(t, in, enc)

	err := m.DecryptFile(in, "", "pw")
	if err == nil || !strings.Contains(err.Error(), "use -out") {
		t.Fatalf("expected inference error, got %v", err)
	}
	if !bytes.Equal(readFile(t, in), enc) {
		t.Fatal("encrypted input must be left untouched")
	}

	out := filepath.Join(dir, "blob.txt")
	if err := m.DecryptFile(in, out, "pw"); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, out)) != "hello" {
		t.Fatal("explicit -out should work")
	}
}

func TestOutputMustDifferFromInput(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))

	if err := m.EncryptFile(in, in, "pw"); err == nil {
		t.Fatal("encrypt must refuse output == input")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("input was clobbered")
	}

	// same file through a different spelling of the path
	if err := m.EncryptFile(in, filepath.Join(dir, ".", "a.txt"), "pw"); err == nil {
		t.Fatal("encrypt must refuse equivalent paths")
	}

	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	enc := readFile(t, in+".enc")
	if err := m.DecryptFile(in+".enc", in+".enc", "pw"); err == nil {
		t.Fatal("decrypt must refuse output == input")
	}
	if !bytes.Equal(readFile(t, in+".enc"), enc) {
		t.Fatal("encrypted input was clobbered")
	}
}

func TestOutputMustDifferFromInputViaSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "a.txt")
	link := filepath.Join(dir, "link.txt")
	writeFile(t, in, []byte("hello"))
	if err := os.Symlink(in, link); err != nil {
		t.Skip("symlink unsupported")
	}
	if err := NewCipherManager().EncryptFile(in, link, "pw"); err == nil {
		t.Fatal("encrypt must refuse a symlink to the input as output")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("input was clobbered")
	}
}

func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".bitseal-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := writeFileAtomic(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, path)) != "two" {
		t.Fatal("content not replaced")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("mode = %v", fi.Mode().Perm())
		}
	}
	if l := tempLeftovers(t, dir); len(l) != 0 {
		t.Fatalf("temp files left behind: %v", l)
	}
}

func TestWriteFileAtomicTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	writeFile(t, path, []byte("old")) // 0644
	if err := writeFileAtomic(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestWriteFileAtomicFailureKeepsExistingAndCleansUp(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing directory", func(t *testing.T) {
		if err := writeFileAtomic(filepath.Join(dir, "nope", "f"), []byte("x"), 0600); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rename onto a directory fails", func(t *testing.T) {
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(target, "keep"), []byte("keep"))
		if err := writeFileAtomic(target, []byte("x"), 0600); err == nil {
			t.Fatal("expected error")
		}
		if string(readFile(t, filepath.Join(target, "keep"))) != "keep" {
			t.Fatal("existing target was damaged")
		}
		if l := tempLeftovers(t, dir); len(l) != 0 {
			t.Fatalf("temp files left behind: %v", l)
		}
	})
}

func TestFileOpsLeaveNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "b.txt"), "pw"); err != nil {
		t.Fatal(err)
	}
	if err := m.DecryptFile(in+".enc", filepath.Join(dir, "c.txt"), "wrong"); err == nil {
		t.Fatal("expected failure")
	}
	if l := tempLeftovers(t, dir); len(l) != 0 {
		t.Fatalf("temp files left behind: %v", l)
	}
}

func TestDecryptFileWrongPasswordLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", "right"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.txt")
	if err := m.DecryptFile(in+".enc", out, "wrong"); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("no plaintext output may exist after a failed decrypt")
	}
}

func TestDecryptFileWrongPasswordKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "a.txt")
	writeFile(t, in, []byte("hello"))
	if err := m.EncryptFile(in, "", "right"); err != nil {
		t.Fatal(err)
	}
	// plaintext "a.txt" still exists and must survive a failed decrypt
	if err := m.DecryptFile(in+".enc", "", "wrong"); err == nil {
		t.Fatal("expected failure")
	}
	if string(readFile(t, in)) != "hello" {
		t.Fatal("existing file was clobbered by a failed decrypt")
	}
}

func TestDecryptFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	out := filepath.Join(dir, "out")

	cases := map[string][]byte{
		"empty file":          {},
		"unknown version 0":   append([]byte{0}, make([]byte, 64)...),
		"unknown version 3":   append([]byte{3}, make([]byte, 64)...),
		"unknown version 255": append([]byte{255}, make([]byte, 64)...),
		"plain text file":     []byte("this is not an encrypted file at all, really"),
		"version only v1":     {1},
		"version only v2":     {2},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			in := filepath.Join(dir, "in.enc")
			writeFile(t, in, data)
			if err := m.DecryptFile(in, out, "pw"); err == nil {
				t.Fatal("expected error")
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("no output may be written on failure")
			}
		})
	}

	t.Run("missing input", func(t *testing.T) {
		if err := m.DecryptFile(filepath.Join(dir, "nope.enc"), out, "pw"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unwritable output dir", func(t *testing.T) {
		in := filepath.Join(dir, "ok.txt")
		writeFile(t, in, []byte("x"))
		if err := m.EncryptFile(in, "", "pw"); err != nil {
			t.Fatal(err)
		}
		if err := m.DecryptFile(in+".enc", filepath.Join(dir, "missing", "o"), "pw"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestUnsupportedVersionErrorMessage(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.enc")
	writeFile(t, in, append([]byte{42}, make([]byte, 64)...))
	err := NewCipherManager().DecryptFile(in, filepath.Join(dir, "o"), "pw")
	if err == nil || err.Error() != "unsupported encryption version: 42" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptFileRoutesByVersionByte(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, err := c.Encrypt([]byte("routed"), []byte("pw"))
			if err != nil {
				t.Fatal(err)
			}
			in := filepath.Join(dir, name+".enc")
			out := filepath.Join(dir, name+".txt")
			writeFile(t, in, enc)
			if err := m.DecryptFile(in, out, "pw"); err != nil {
				t.Fatal(err)
			}
			if string(readFile(t, out)) != "routed" {
				t.Fatal("wrong plaintext")
			}
		})
	}
}

func TestDecryptGoldenFiles(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	for name, h := range map[string]string{"v1": goldenV1Hex, "v2": goldenV2Hex} {
		t.Run(name, func(t *testing.T) {
			in := filepath.Join(dir, name+".enc")
			out := filepath.Join(dir, name+".txt")
			writeFile(t, in, mustHex(t, h))
			if err := m.DecryptFile(in, out, "golden-pw"); err != nil {
				t.Fatal(err)
			}
			if string(readFile(t, out)) != "golden plaintext" {
				t.Fatal("wrong plaintext")
			}
		})
	}
}

func TestFileRoundTripEdgeCases(t *testing.T) {
	m := NewCipherManager()
	cases := map[string][]byte{
		"empty":  {},
		"binary": {0x00, 0xff, 0x10, 0x80},
	}
	if !testing.Short() {
		cases["big"] = bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "f")
			writeFile(t, in, content)
			if err := m.EncryptFile(in, "", "pw"); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "g")
			if err := m.DecryptFile(in+".enc", out, "pw"); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readFile(t, out), content) {
				t.Fatal("content mismatch")
			}
		})
	}
}

func TestReencryptUpgradesV1ToV2(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	v1, _ := NewCipherV1().Encrypt([]byte("legacy"), []byte("pw"))
	legacy := filepath.Join(dir, "x.enc")
	writeFile(t, legacy, v1)

	plain := filepath.Join(dir, "x")
	if err := m.DecryptFile(legacy, plain, "pw"); err != nil {
		t.Fatal(err)
	}
	upgraded := filepath.Join(dir, "x.v2.enc")
	if err := m.EncryptFile(plain, upgraded, "pw"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, upgraded)[0] != 2 {
		t.Fatal("re-encrypted file should be V2")
	}
	out := filepath.Join(dir, "y")
	if err := m.DecryptFile(upgraded, out, "pw"); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, out)) != "legacy" {
		t.Fatal("content lost during upgrade")
	}
}

func TestFilenamesWithSpacesAndUnicode(t *testing.T) {
	dir := t.TempDir()
	m := NewCipherManager()
	in := filepath.Join(dir, "my secret é日本.txt")
	writeFile(t, in, []byte("hi"))
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	os.Remove(in)
	if err := m.DecryptFile(in+".enc", "", "pw"); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, in)) != "hi" {
		t.Fatal("mismatch")
	}
}
