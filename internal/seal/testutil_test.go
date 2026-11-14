package seal

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/dterana/bitseal/internal/testutil"
)

var (
	pattern         = testutil.Pattern
	mustHex         = testutil.MustHex
	writeFile       = testutil.WriteFile
	readFile        = testutil.ReadFile
	tempLeftovers   = testutil.TempLeftovers
	noTempLeftovers = testutil.NoTempLeftovers
)

// fastKDF keeps Argon2 cheap so the suite exercises many cases quickly. The
// real defaults are covered by the golden vectors and the end-to-end tests.
var fastKDF = KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

// tinyChunk makes multi-chunk files out of a few hundred bytes.
const tinyChunk = 4 // 16 byte chunks

func sec(pw string) Secret { return Secret{Password: []byte(pw)} }

func secKF(pw, keyFile string) Secret {
	return Secret{Password: []byte(pw), KeyFile: []byte(keyFile)}
}

func fastV2() *CipherV2 { return newCipherV2With(fastKDF, 6) }

func tinyV2() *CipherV2 { return newCipherV2With(fastKDF, tinyChunk) }

func fastManager() *Manager { return NewManagerWith(fastKDF, 6) }

// stdioManager returns a fast manager wired to in-memory streams, for the
// tests of the "-" paths.
func stdioManager(input string) (*Manager, *bytes.Buffer) {
	m := fastManager()
	out := &bytes.Buffer{}
	m.In = strings.NewReader(input)
	m.Out = out
	m.OutIsTerminal = func() bool { return false }
	return m, out
}

// allCiphers returns one cipher for every registered version, so a newly
// added version is covered by the generic tests without editing them, plus
// the V2 configurations that exercise different chunk sizes.
func allCiphers() map[string]CipherVersion {
	out := map[string]CipherVersion{}
	for _, v := range Versions() {
		c, _ := newCipher(v, Params{KDF: fastKDF, ChunkLog2: 6})
		out[fmt.Sprintf("v%d", v)] = c
	}
	out["v2-default-chunk"] = newCipherV2With(fastKDF, DefaultChunkLog2)
	out["v2-tiny-chunk"] = tinyV2()
	return out
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
