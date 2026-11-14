// Package seal implements Bitseal's versioned file encryption: the cipher
// versions, their registry, and the file operations built on them.
//
// Every encrypted file starts with a version byte that selects the cipher
// that reads it. A cipher version lives in its own file and registers itself
// in an init function (see crypto_v1.go and crypto_v2.go), so adding a
// version never requires touching the manager. The on-disk formats are
// specified in docs/format.md.
package seal

import (
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
)

const (
	KeySize    = 32 // 256-bit for AES-256
	NonceSize  = 12 // GCM standard
	gcmTagSize = 16
)

// Secret is what unlocks a file: a password, and optionally a key file that
// acts as a second factor.
type Secret struct {
	Password []byte
	KeyFile  []byte
}

func (s Secret) hasKeyFile() bool { return len(s.KeyFile) > 0 }

// material returns the bytes fed to the KDF. With a key file it is a fresh
// slice (password || SHA-256(key file)) that the caller should wipe.
func (s Secret) material() []byte {
	if !s.hasKeyFile() {
		return s.Password
	}
	sum := sha256.Sum256(s.KeyFile)
	m := make([]byte, 0, len(s.Password)+sha256.Size)
	m = append(m, s.Password...)
	return append(m, sum[:]...)
}

// Wipe zeroes the secret's buffers. Best effort: copies made by the runtime
// or by buffered readers cannot be reached.
func (s Secret) Wipe() {
	Wipe(s.Password)
	Wipe(s.KeyFile)
}

// Wipe zeroes b.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// FileInfo describes an encrypted file's format, read from its header alone.
type FileInfo struct {
	Version   byte
	Cipher    string
	KDF       string
	KeyFile   bool
	ChunkSize int // 0 when the file is a single authenticated block
	Legacy    bool
}

// CipherVersion defines the interface for different encryption versions
type CipherVersion interface {
	Version() byte
	Encrypt(plaintext []byte, secret Secret) ([]byte, error)
	Decrypt(ciphertext []byte, secret Secret) ([]byte, error)
	// Inspect reads only the header from src and describes the format.
	Inspect(src io.Reader) (FileInfo, error)
}

// StreamCipher is implemented by versions that can process data of any size
// with bounded memory.
type StreamCipher interface {
	CipherVersion
	EncryptStream(dst io.Writer, src io.Reader, secret Secret) error
	DecryptStream(dst io.Writer, src io.Reader, secret Secret) error
}

// Params are the tunable settings handed to every cipher factory. A cipher
// uses the ones that apply to it when encrypting; when decrypting it always
// follows what the file's own header says.
type Params struct {
	KDF       KDFParams
	ChunkLog2 uint8
}

// DefaultParams are used by NewManager.
var DefaultParams = Params{KDF: DefaultKDF, ChunkLog2: DefaultChunkLog2}

type factory func(Params) CipherVersion

var registry = map[byte]factory{}

// register adds a cipher version. It is called from init functions.
func register(version byte, f factory) {
	if _, dup := registry[version]; dup {
		panic(fmt.Sprintf("seal: cipher version %d registered twice", version))
	}
	registry[version] = f
}

// Versions returns the registered cipher versions in ascending order.
func Versions() []byte {
	out := make([]byte, 0, len(registry))
	for v := range registry {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// newCipher instantiates a registered version with the given parameters.
func newCipher(version byte, p Params) (CipherVersion, bool) {
	f, ok := registry[version]
	if !ok {
		return nil, false
	}
	return f(p), true
}
