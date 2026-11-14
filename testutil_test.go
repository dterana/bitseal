package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fastKDF keeps Argon2 cheap so the suite exercises many cases quickly. The
// real defaults are covered by the golden vectors and the end-to-end tests.
var fastKDF = kdfParams{Time: 1, MemoryKiB: 64, Threads: 1}

// tinyChunk makes multi-chunk files out of a few hundred bytes.
const tinyChunk = 4 // 16 byte chunks

func sec(pw string) Secret { return Secret{Password: []byte(pw)} }

func secKF(pw, keyFile string) Secret {
	return Secret{Password: []byte(pw), KeyFile: []byte(keyFile)}
}

func fastV2() *CipherV2 { return newCipherV2With(fastKDF, 6) }

func tinyV2() *CipherV2 { return newCipherV2With(fastKDF, tinyChunk) }

func fastManager() *CipherManager { return newCipherManagerWith(fastKDF, 6) }

func allCiphers() map[string]CipherVersion {
	return map[string]CipherVersion{
		"v1":         NewCipherV1(),
		"v2":         fastV2(),
		"v2-default": newCipherV2With(fastKDF, defaultChunkLog2),
		"v2-tiny":    tinyV2(),
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

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

func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".bitseal-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func noTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	if l := tempLeftovers(t, dir); len(l) != 0 {
		t.Fatalf("temp files left behind: %v", l)
	}
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// errWriter fails after n bytes have been accepted.
type errWriter struct{ left int }

func (w *errWriter) Write(p []byte) (int, error) {
	if len(p) > w.left {
		n := w.left
		w.left = 0
		return n, io.ErrShortWrite
	}
	w.left -= len(p)
	return len(p), nil
}

// errReader yields data and then fails instead of reporting EOF.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// stdio redirects the process streams for in-process CLI tests.
type stdio struct {
	out, err *bytes.Buffer
}

func captureStdio(t *testing.T, input string) *stdio {
	t.Helper()
	oldIn, oldOut, oldErr := stdin, stdout, stderr
	oldIs, oldOutIs, oldRead, oldMgr := stdinIsTerminal, stdoutIsTerminal, readTerminalSecret, newManager
	t.Cleanup(func() {
		stdin, stdout, stderr = oldIn, oldOut, oldErr
		stdinIsTerminal, stdoutIsTerminal, readTerminalSecret, newManager = oldIs, oldOutIs, oldRead, oldMgr
	})

	s := &stdio{out: &bytes.Buffer{}, err: &bytes.Buffer{}}
	stdin = strings.NewReader(input)
	stdout, stderr = s.out, s.err
	stdinIsTerminal = func() bool { return false }
	stdoutIsTerminal = func() bool { return false }
	newManager = fastManager
	return s
}

// fakeTerminal makes stdin look like a terminal that types the given secrets.
func fakeTerminal(t *testing.T, secrets ...string) {
	t.Helper()
	stdinIsTerminal = func() bool { return true }
	i := 0
	readTerminalSecret = func() ([]byte, error) {
		if i >= len(secrets) {
			return nil, io.EOF
		}
		s := secrets[i]
		i++
		return []byte(s), nil
	}
}
