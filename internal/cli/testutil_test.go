package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/dterana/bitseal/internal/seal"
	"github.com/dterana/bitseal/internal/testutil"
)

var (
	pattern         = testutil.Pattern
	mustHex         = testutil.MustHex
	writeFile       = testutil.WriteFile
	readFile        = testutil.ReadFile
	noTempLeftovers = testutil.NoTempLeftovers
)

// fastKDF keeps Argon2 cheap; the end-to-end tests in cmd/bitseal cover the
// real parameters.
var fastKDF = seal.KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

func fastManager() *seal.Manager { return seal.NewManagerWith(fastKDF, 6) }

func sec(pw string) seal.Secret { return seal.Secret{Password: []byte(pw)} }

func secKF(pw, keyFile string) seal.Secret {
	return seal.Secret{Password: []byte(pw), KeyFile: []byte(keyFile)}
}

// stdio is an App wired to in-memory streams with a cheap KDF.
type stdio struct {
	*App
	out, err *bytes.Buffer
}

func captureStdio(t *testing.T, input string) *stdio {
	t.Helper()
	s := &stdio{out: &bytes.Buffer{}, err: &bytes.Buffer{}}
	s.App = &App{
		Stdin:              strings.NewReader(input),
		Stdout:             s.out,
		Stderr:             s.err,
		StdinIsTerminal:    func() bool { return false },
		StdoutIsTerminal:   func() bool { return false },
		ReadTerminalSecret: func() ([]byte, error) { return nil, io.EOF },
		NewManager:         fastManager,
		Version:            "9.9.9-test",
		Build:              "testbuild",
	}
	return s
}

// fakeTerminal makes stdin look like a terminal that types the given secrets.
func fakeTerminal(s *stdio, secrets ...string) {
	s.StdinIsTerminal = func() bool { return true }
	i := 0
	s.ReadTerminalSecret = func() ([]byte, error) {
		if i >= len(secrets) {
			return nil, io.EOF
		}
		v := secrets[i]
		i++
		return []byte(v), nil
	}
}

func writeV1File(t *testing.T, path, content, pw string) {
	t.Helper()
	enc, err := seal.NewCipherV1().Encrypt([]byte(content), sec(pw))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, enc)
}

func decryptedContent(t *testing.T, m *seal.Manager, path string, s seal.Secret) (string, error) {
	t.Helper()
	out := t.TempDir() + "/plain"
	if err := m.DecryptFile(path, out, s); err != nil {
		return "", err
	}
	return string(readFile(t, out)), nil
}
