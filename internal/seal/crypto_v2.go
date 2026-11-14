// ============================================================================
// CipherV2: chunked AES-256-GCM with Argon2id and a self-describing header
// ============================================================================
//
// Format:
//
//	[version:1][flags:1][chunkLog2:1][time:4][memoryKiB:4][threads:1][salt:16][noncePrefix:7]
//	followed by one or more sealed chunks of (1<<chunkLog2) plaintext bytes + 16 byte tag.
//
// Every chunk is sealed with the whole header as additional data, so the KDF
// parameters, flags and salt are authenticated. The chunk nonce is
// noncePrefix || counter(4, big endian) || final(1), which makes reordering,
// duplicating, dropping and truncating chunks detectable (STREAM construction).

package seal

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSizeV2        = 16
	noncePrefixSizeV2 = 7
	headerSizeV2      = 1 + 1 + 1 + 4 + 4 + 1 + SaltSizeV2 + noncePrefixSizeV2

	flagKeyFile  byte = 1 << 0
	knownFlagsV2      = flagKeyFile

	minChunkLog2     = 4
	maxChunkLog2     = 24
	DefaultChunkLog2 = 16 // 64 KiB

	maxKDFThreads = 64
)

func init() {
	register(2, func(p Params) CipherVersion { return newCipherV2With(p.KDF, p.ChunkLog2) })
}

// KDFParams are the Argon2id cost parameters, stored in every V2 header so
// the defaults can be raised later without a new cipher version.
type KDFParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// Upper bounds applied to parameters read from untrusted files, so a crafted
// header cannot make decryption allocate unbounded memory.
var (
	maxKDFTime      uint32 = 64
	maxKDFMemoryKiB uint32 = 1 << 20 // 1 GiB
)

func (k KDFParams) validate() error {
	switch {
	case k.Threads < 1 || k.Threads > maxKDFThreads:
		return fmt.Errorf("invalid KDF threads: %d", k.Threads)
	case k.Time < 1 || k.Time > maxKDFTime:
		return fmt.Errorf("invalid KDF time cost: %d", k.Time)
	case k.MemoryKiB < 8*uint32(k.Threads) || k.MemoryKiB > maxKDFMemoryKiB:
		return fmt.Errorf("invalid KDF memory cost: %d KiB", k.MemoryKiB)
	}
	return nil
}

// CipherV2 encrypts with the parameters it was created with and decrypts
// with the parameters found in each file's header.
type CipherV2 struct {
	kdf       KDFParams
	chunkLog2 uint8
}

func NewCipherV2() *CipherV2 {
	return &CipherV2{kdf: DefaultKDF, chunkLog2: DefaultChunkLog2}
}

func newCipherV2With(kdf KDFParams, chunkLog2 uint8) *CipherV2 {
	return &CipherV2{kdf: kdf, chunkLog2: chunkLog2}
}

func (c *CipherV2) Version() byte { return 2 }

type headerV2 struct {
	flags       byte
	chunkLog2   uint8
	kdf         KDFParams
	salt        [SaltSizeV2]byte
	noncePrefix [noncePrefixSizeV2]byte
}

func (h headerV2) marshal() []byte {
	b := make([]byte, headerSizeV2)
	b[0] = 2
	b[1] = h.flags
	b[2] = h.chunkLog2
	binary.BigEndian.PutUint32(b[3:], h.kdf.Time)
	binary.BigEndian.PutUint32(b[7:], h.kdf.MemoryKiB)
	b[11] = h.kdf.Threads
	copy(b[12:], h.salt[:])
	copy(b[12+SaltSizeV2:], h.noncePrefix[:])
	return b
}

func parseHeaderV2(b []byte) (headerV2, error) {
	var h headerV2
	if len(b) < headerSizeV2 {
		return h, fmt.Errorf("invalid encrypted file format (too short)")
	}
	if b[0] != 2 {
		return h, fmt.Errorf("not a version 2 file")
	}
	h.flags = b[1]
	if h.flags&^knownFlagsV2 != 0 {
		return h, fmt.Errorf("unsupported file flags: 0x%02x (file made by a newer Bitseal?)", h.flags)
	}
	h.chunkLog2 = b[2]
	if h.chunkLog2 < minChunkLog2 || h.chunkLog2 > maxChunkLog2 {
		return h, fmt.Errorf("invalid chunk size exponent: %d", h.chunkLog2)
	}
	h.kdf = KDFParams{
		Time:      binary.BigEndian.Uint32(b[3:]),
		MemoryKiB: binary.BigEndian.Uint32(b[7:]),
		Threads:   b[11],
	}
	if err := h.kdf.validate(); err != nil {
		return h, err
	}
	copy(h.salt[:], b[12:])
	copy(h.noncePrefix[:], b[12+SaltSizeV2:])
	return h, nil
}

func newAEADV2(h headerV2, secret Secret) (cipher.AEAD, error) {
	material := secret.material()
	if secret.hasKeyFile() {
		defer Wipe(material)
	}
	key := argon2.IDKey(material, h.salt[:], h.kdf.Time, h.kdf.MemoryKiB, h.kdf.Threads, KeySize)
	defer Wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return aead, nil
}

func chunkNonce(prefix [noncePrefixSizeV2]byte, counter uint32, last bool) []byte {
	n := make([]byte, NonceSize)
	copy(n, prefix[:])
	binary.BigEndian.PutUint32(n[noncePrefixSizeV2:], counter)
	if last {
		n[NonceSize-1] = 1
	}
	return n
}

func (c *CipherV2) EncryptStream(dst io.Writer, src io.Reader, secret Secret) error {
	if len(secret.Password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}
	if err := c.kdf.validate(); err != nil {
		return err
	}
	if c.chunkLog2 < minChunkLog2 || c.chunkLog2 > maxChunkLog2 {
		return fmt.Errorf("invalid chunk size exponent: %d", c.chunkLog2)
	}

	h := headerV2{chunkLog2: c.chunkLog2, kdf: c.kdf}
	if secret.hasKeyFile() {
		h.flags |= flagKeyFile
	}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	if _, err := rand.Read(h.noncePrefix[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	aead, err := newAEADV2(h, secret)
	if err != nil {
		return err
	}

	header := h.marshal()
	if _, err := dst.Write(header); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	chunkSize := 1 << h.chunkLog2
	br := bufio.NewReaderSize(src, chunkSize+1)
	plain := make([]byte, chunkSize)
	defer Wipe(plain)
	sealed := make([]byte, 0, chunkSize+gcmTagSize)

	for counter := uint32(0); ; counter++ {
		n, err := io.ReadFull(br, plain)
		last := false
		switch err {
		case nil:
			// A full chunk is the last one only if nothing follows it.
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return fmt.Errorf("failed to read input: %w", perr)
			}
		case io.EOF, io.ErrUnexpectedEOF:
			last = true
		default:
			return fmt.Errorf("failed to read input: %w", err)
		}

		sealed = aead.Seal(sealed[:0], chunkNonce(h.noncePrefix, counter, last), plain[:n], header)
		if _, err := dst.Write(sealed); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		if last {
			return nil
		}
		if counter == math.MaxUint32 {
			return fmt.Errorf("input too large")
		}
	}
}

func (c *CipherV2) DecryptStream(dst io.Writer, src io.Reader, secret Secret) error {
	header := make([]byte, headerSizeV2)
	if _, err := io.ReadFull(src, header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("invalid encrypted file format (too short)")
		}
		return fmt.Errorf("failed to read input: %w", err)
	}
	h, err := parseHeaderV2(header)
	if err != nil {
		return err
	}

	needsKeyFile := h.flags&flagKeyFile != 0
	switch {
	case needsKeyFile && !secret.hasKeyFile():
		return fmt.Errorf("this file requires a key file (-keyfile)")
	case !needsKeyFile && secret.hasKeyFile():
		return fmt.Errorf("this file was not encrypted with a key file")
	}

	aead, err := newAEADV2(h, secret)
	if err != nil {
		return err
	}

	chunkSize := 1 << h.chunkLog2
	br := bufio.NewReaderSize(src, chunkSize+gcmTagSize+1)
	sealed := make([]byte, chunkSize+gcmTagSize)
	plain := make([]byte, 0, chunkSize)
	defer func() { Wipe(plain[:cap(plain)]) }()

	for counter := uint32(0); ; counter++ {
		n, err := io.ReadFull(br, sealed)
		last := false
		switch err {
		case nil:
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return fmt.Errorf("failed to read input: %w", perr)
			}
		case io.ErrUnexpectedEOF:
			last = true
		case io.EOF:
			return fmt.Errorf("invalid encrypted file format (too short)")
		default:
			return fmt.Errorf("failed to read input: %w", err)
		}
		if n < gcmTagSize {
			return fmt.Errorf("invalid encrypted file format (too short)")
		}

		out, err := aead.Open(plain[:0], chunkNonce(h.noncePrefix, counter, last), sealed[:n], header)
		if err != nil {
			return fmt.Errorf("decryption failed (wrong password or corrupted file): %w", err)
		}
		if _, err := dst.Write(out); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		if last {
			return nil
		}
		if counter == math.MaxUint32 {
			return fmt.Errorf("input too large")
		}
	}
}

func (c *CipherV2) Encrypt(plaintext []byte, secret Secret) ([]byte, error) {
	var out bytes.Buffer
	if err := c.EncryptStream(&out, bytes.NewReader(plaintext), secret); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c *CipherV2) Decrypt(ciphertext []byte, secret Secret) ([]byte, error) {
	if len(ciphertext) < headerSizeV2+gcmTagSize {
		return nil, fmt.Errorf("invalid encrypted file format (too short)")
	}
	var out bytes.Buffer
	if err := c.DecryptStream(&out, bytes.NewReader(ciphertext), secret); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c *CipherV2) Inspect(src io.Reader) (FileInfo, error) {
	header := make([]byte, headerSizeV2)
	if _, err := io.ReadFull(src, header); err != nil {
		return FileInfo{}, fmt.Errorf("invalid encrypted file format (too short)")
	}
	h, err := parseHeaderV2(header)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Version: 2,
		Cipher:  "AES-256-GCM (chunked)",
		KDF: fmt.Sprintf("Argon2id (time=%d, memory=%d MiB, threads=%d), random per-file salt",
			h.kdf.Time, h.kdf.MemoryKiB/1024, h.kdf.Threads),
		KeyFile:   h.flags&flagKeyFile != 0,
		ChunkSize: 1 << h.chunkLog2,
	}, nil
}
