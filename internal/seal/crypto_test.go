package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/dterana/casemate/internal/testvectors"
)

func TestCipherVersionBytes(t *testing.T) {
	if NewCipherV1().Version() != 1 || NewCipherV2().Version() != 2 {
		t.Fatal("unexpected version bytes")
	}
}

func TestRoundTrip(t *testing.T) {
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	big := make([]byte, 1<<20+7)
	rand.Read(big)

	plaintexts := map[string][]byte{
		"empty":       {},
		"one byte":    {0x42},
		"short text":  []byte("secret"),
		"newlines":    []byte("a\nb\r\nc\n"),
		"unicode":     []byte("héllo wörld 日本語 🔒"),
		"all bytes":   allBytes,
		"nul bytes":   {0, 0, 0, 0},
		"yaml secret": []byte("authtoken: abc123\nregion: eu\n"),
		"pattern 1k":  pattern(1000),
	}
	if !testing.Short() {
		plaintexts["1 MiB+7"] = big
	}
	passwords := map[string]string{
		"simple":  "pw",
		"spaces":  "correct horse battery staple",
		"unicode": "pässwörd-日本語-🔑",
		"long":    strings.Repeat("x", 4096),
		"symbols": `!@#$%^&*()_+-=[]{}|;':",./<>?` + "`~\\",
	}

	for cname, c := range allCiphers() {
		check := func(t *testing.T, pt []byte, pw string) {
			enc, err := c.Encrypt(pt, sec(pw))
			if err != nil {
				t.Fatal(err)
			}
			if enc[0] != c.Version() {
				t.Fatalf("version byte = %d, want %d", enc[0], c.Version())
			}
			dec, err := c.Decrypt(enc, sec(pw))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dec, pt) {
				t.Fatal("plaintext mismatch after round trip")
			}
		}
		for pname, pt := range plaintexts {
			t.Run(cname+"/plaintext/"+pname, func(t *testing.T) { check(t, pt, "pw") })
		}
		for pwname, pw := range passwords {
			t.Run(cname+"/password/"+pwname, func(t *testing.T) { check(t, []byte("secret"), pw) })
		}
	}
}

func TestEncryptDoesNotMutateInputs(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			pt := []byte("immutable plaintext")
			pw := []byte("pw")
			ptCopy := append([]byte(nil), pt...)
			pwCopy := append([]byte(nil), pw...)
			enc, err := c.Encrypt(pt, Secret{Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			encCopy := append([]byte(nil), enc...)
			if _, err := c.Decrypt(enc, Secret{Password: pw}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, ptCopy) || !bytes.Equal(pw, pwCopy) || !bytes.Equal(enc, encCopy) {
				t.Fatal("inputs were mutated")
			}
		})
	}
}

func TestEncryptEmptyPasswordRejected(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			for _, pw := range [][]byte{nil, {}} {
				if _, err := c.Encrypt([]byte("x"), Secret{Password: pw}); err == nil {
					t.Fatal("empty password should be rejected")
				}
			}
		})
	}
}

func TestWrongPasswordFails(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("secret"), sec("right"))
			for _, bad := range []string{"wrong", "Right", "right ", " right", "righ", "rightt", ""} {
				_, err := c.Decrypt(enc, sec(bad))
				if err == nil {
					t.Fatalf("password %q should fail", bad)
				}
				if !strings.Contains(err.Error(), "decryption failed") {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestOutputRandomized(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			a, _ := c.Encrypt([]byte("same"), sec("pw"))
			b, _ := c.Encrypt([]byte("same"), sec("pw"))
			if bytes.Equal(a, b) {
				t.Fatal("two encryptions of the same data must differ")
			}
		})
	}
}

func TestCipherV1StaticSalt(t *testing.T) {
	c := NewCipherV1()
	if !bytes.Equal(c.deriveKey([]byte("pw")), c.deriveKey([]byte("pw"))) {
		t.Fatal("V1 key derivation must be deterministic")
	}
}

func TestCipherV2PerFileSaltAndNoncePrefix(t *testing.T) {
	c := fastV2()
	salts, prefixes := map[string]bool{}, map[string]bool{}
	for i := 0; i < 20; i++ {
		enc, err := c.Encrypt([]byte("x"), sec("pw"))
		if err != nil {
			t.Fatal(err)
		}
		h, err := parseHeaderV2(enc)
		if err != nil {
			t.Fatal(err)
		}
		if salts[string(h.salt[:])] || prefixes[string(h.noncePrefix[:])] {
			t.Fatal("salt or nonce prefix reused across files")
		}
		salts[string(h.salt[:])] = true
		prefixes[string(h.noncePrefix[:])] = true
	}
}

// ----------------------------------------------------------------------------
// V2 header
// ----------------------------------------------------------------------------

func TestCipherV2HeaderFields(t *testing.T) {
	kdf := KDFParams{Time: 2, MemoryKiB: 128, Threads: 2}
	enc, err := newCipherV2With(kdf, 9).Encrypt([]byte("x"), sec("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 2 || enc[1] != 0 || enc[2] != 9 {
		t.Fatalf("version/flags/chunk = %d/%d/%d", enc[0], enc[1], enc[2])
	}
	if binary.BigEndian.Uint32(enc[3:]) != 2 || binary.BigEndian.Uint32(enc[7:]) != 128 || enc[11] != 2 {
		t.Fatal("KDF parameters not stored in the header")
	}

	enc, _ = newCipherV2With(kdf, 9).Encrypt([]byte("x"), secKF("pw", "kf"))
	if enc[1] != flagKeyFile {
		t.Fatalf("flags = %d, want key file flag", enc[1])
	}
}

func TestHeaderMarshalParseRoundTrip(t *testing.T) {
	h := headerV2{flags: flagKeyFile, chunkLog2: 12, kdf: KDFParams{Time: 5, MemoryKiB: 4096, Threads: 3}}
	rand.Read(h.salt[:])
	rand.Read(h.noncePrefix[:])
	b := h.marshal()
	if len(b) != headerSizeV2 {
		t.Fatalf("len = %d, want %d", len(b), headerSizeV2)
	}
	got, err := parseHeaderV2(b)
	if err != nil || got != h {
		t.Fatalf("got %+v, %v; want %+v", got, err, h)
	}
}

func TestParseHeaderV2Validation(t *testing.T) {
	good := headerV2{chunkLog2: 16, kdf: fastKDF}
	mutate := func(f func(b []byte)) []byte {
		b := good.marshal()
		f(b)
		return b
	}
	cases := map[string][]byte{
		"empty":             {},
		"short":             good.marshal()[:headerSizeV2-1],
		"version 1":         mutate(func(b []byte) { b[0] = 1 }),
		"version 3":         mutate(func(b []byte) { b[0] = 3 }),
		"unknown flag":      mutate(func(b []byte) { b[1] = 0x02 }),
		"all flags":         mutate(func(b []byte) { b[1] = 0xff }),
		"chunk exp too low": mutate(func(b []byte) { b[2] = minChunkLog2 - 1 }),
		"chunk exp too big": mutate(func(b []byte) { b[2] = maxChunkLog2 + 1 }),
		"time zero":         mutate(func(b []byte) { binary.BigEndian.PutUint32(b[3:], 0) }),
		"time too big":      mutate(func(b []byte) { binary.BigEndian.PutUint32(b[3:], maxKDFTime+1) }),
		"memory zero":       mutate(func(b []byte) { binary.BigEndian.PutUint32(b[7:], 0) }),
		"memory huge":       mutate(func(b []byte) { binary.BigEndian.PutUint32(b[7:], 1<<31) }),
		"memory over cap":   mutate(func(b []byte) { binary.BigEndian.PutUint32(b[7:], maxKDFMemoryKiB+1) }),
		"memory < 8*thr":    mutate(func(b []byte) { b[11] = 8; binary.BigEndian.PutUint32(b[7:], 63) }),
		"threads zero":      mutate(func(b []byte) { b[11] = 0 }),
		"threads too many":  mutate(func(b []byte) { b[11] = maxKDFThreads + 1 }),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeaderV2(b); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := parseHeaderV2(good.marshal()); err != nil {
		t.Fatalf("good header rejected: %v", err)
	}
}

// A hostile header must be rejected before any memory is allocated for it.
func TestDecryptRejectsHostileKDFBeforeAllocating(t *testing.T) {
	h := headerV2{chunkLog2: 16, kdf: KDFParams{Time: 1, MemoryKiB: 1 << 31, Threads: 1}}
	data := append(h.marshal(), make([]byte, 64)...)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := fastV2().Decrypt(data, sec("pw"))
	runtime.ReadMemStats(&after)

	if err == nil || !strings.Contains(err.Error(), "KDF memory") {
		t.Fatalf("unexpected error: %v", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("allocated %d bytes while rejecting a hostile header", grew)
	}
}

func TestDecryptUsesParametersFromHeader(t *testing.T) {
	enc, err := newCipherV2With(KDFParams{Time: 2, MemoryKiB: 128, Threads: 2}, 7).Encrypt(pattern(500), sec("pw"))
	if err != nil {
		t.Fatal(err)
	}
	// a cipher configured with entirely different defaults must still decrypt
	other := newCipherV2With(KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}, 5)
	dec, err := other.Decrypt(enc, sec("pw"))
	if err != nil || !bytes.Equal(dec, pattern(500)) {
		t.Fatalf("decrypt with header params failed: %v", err)
	}
}

func TestEncryptRejectsInvalidConfiguration(t *testing.T) {
	bad := []*CipherV2{
		newCipherV2With(KDFParams{Time: 0, MemoryKiB: 64, Threads: 1}, 6),
		newCipherV2With(KDFParams{Time: 1, MemoryKiB: 1, Threads: 1}, 6),
		newCipherV2With(KDFParams{Time: 1, MemoryKiB: 64, Threads: 0}, 6),
		newCipherV2With(fastKDF, minChunkLog2-1),
		newCipherV2With(fastKDF, maxChunkLog2+1),
	}
	for i, c := range bad {
		if _, err := c.Encrypt([]byte("x"), sec("pw")); err == nil {
			t.Fatalf("config %d should be rejected", i)
		}
	}
}

func TestDefaultKDFParametersAreSane(t *testing.T) {
	if err := DefaultKDF.validate(); err != nil {
		t.Fatal(err)
	}
	if DefaultKDF.MemoryKiB < 19*1024 || DefaultKDF.Time < 2 {
		t.Fatal("default Argon2id cost fell below the OWASP minimum (m=19 MiB, t=2)")
	}
}

// ----------------------------------------------------------------------------
// V2 chunking
// ----------------------------------------------------------------------------

func TestCipherV2ChunkBoundaries(t *testing.T) {
	const chunk = 16
	sizes := []int{0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 64, 100, 160, 161}
	for _, n := range sizes {
		pt := pattern(n)
		enc, err := tinyV2().Encrypt(pt, sec("pw"))
		if err != nil {
			t.Fatal(err)
		}
		chunks := (n + chunk - 1) / chunk
		if chunks == 0 {
			chunks = 1 // an empty file still has one (empty, final) chunk
		}
		if want := headerSizeV2 + n + chunks*gcmTagSize; len(enc) != want {
			t.Fatalf("n=%d: len = %d, want %d", n, len(enc), want)
		}
		dec, err := tinyV2().Decrypt(enc, sec("pw"))
		if err != nil || !bytes.Equal(dec, pt) {
			t.Fatalf("n=%d: round trip failed: %v", n, err)
		}
	}
}

func TestCipherV2LayoutDefaultChunk(t *testing.T) {
	pt := []byte("hello")
	enc, _ := fastV2().Encrypt(pt, sec("pw"))
	if want := headerSizeV2 + len(pt) + gcmTagSize; len(enc) != want {
		t.Fatalf("len = %d, want %d", len(enc), want)
	}
}

func TestCipherV1Layout(t *testing.T) {
	pt := []byte("hello")
	enc, _ := NewCipherV1().Encrypt(pt, sec("pw"))
	if want := 1 + NonceSize + len(pt) + gcmTagSize; len(enc) != want {
		t.Fatalf("len = %d, want %d", len(enc), want)
	}
}

// chunkRecords splits a tiny-chunk V2 file into header and sealed chunks.
func chunkRecords(t *testing.T, enc []byte) (header []byte, chunks [][]byte) {
	t.Helper()
	header = enc[:headerSizeV2]
	body := enc[headerSizeV2:]
	for len(body) > 0 {
		n := 16 + gcmTagSize
		if n > len(body) {
			n = len(body)
		}
		chunks = append(chunks, append([]byte(nil), body[:n]...))
		body = body[n:]
	}
	return header, chunks
}

func join(header []byte, chunks ...[]byte) []byte {
	out := append([]byte(nil), header...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

func TestCipherV2ChunkTamperingDetected(t *testing.T) {
	// 100 bytes -> 6 full chunks + one partial final chunk
	enc, err := tinyV2().Encrypt(pattern(100), sec("pw"))
	if err != nil {
		t.Fatal(err)
	}
	header, c := chunkRecords(t, enc)
	if len(c) != 7 {
		t.Fatalf("expected 7 chunks, got %d", len(c))
	}
	last := len(c) - 1

	cases := map[string][]byte{
		"swap first two":             join(header, c[1], c[0], c[2], c[3], c[4], c[5], c[6]),
		"swap middle":                join(header, c[0], c[1], c[3], c[2], c[4], c[5], c[6]),
		"duplicate first":            join(header, c[0], c[0], c[1], c[2], c[3], c[4], c[5], c[6]),
		"duplicate a full chunk":     join(header, c[0], c[1], c[2], c[2], c[3], c[4], c[5], c[6]),
		"drop first":                 join(header, c[1], c[2], c[3], c[4], c[5], c[6]),
		"drop middle":                join(header, c[0], c[1], c[3], c[4], c[5], c[6]),
		"drop final":                 join(header, c[0], c[1], c[2], c[3], c[4], c[5]),
		"drop last two":              join(header, c[0], c[1], c[2], c[3], c[4]),
		"append duplicate of first":  join(header, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[0]),
		"append after final":         join(header, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[last]),
		"final moved to front":       join(header, c[6], c[1], c[2], c[3], c[4], c[5], c[0]),
		"header only":                header,
		"header + partial tag":       join(header, c[0][:gcmTagSize-1]),
		"only first chunk (no end)":  join(header, c[0]),
		"first two chunks no end":    join(header, c[0], c[1]),
		"final chunk missing 1 byte": join(header, c[0], c[1], c[2], c[3], c[4], c[5], c[6][:len(c[6])-1]),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tinyV2().Decrypt(data, sec("pw")); err == nil {
				t.Fatal("tampering not detected")
			}
		})
	}

	if dec, err := tinyV2().Decrypt(join(header, c...), sec("pw")); err != nil || !bytes.Equal(dec, pattern(100)) {
		t.Fatalf("untouched file must still decrypt: %v", err)
	}
}

// A file whose length is an exact multiple of the chunk size ends with a full
// final chunk; dropping that chunk must not look like a valid shorter file.
func TestCipherV2ExactMultipleTruncationDetected(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(48), sec("pw")) // 3 full chunks
	header, c := chunkRecords(t, enc)
	if len(c) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(c))
	}
	for k := 0; k < 3; k++ {
		if _, err := tinyV2().Decrypt(join(header, c[:k]...), sec("pw")); err == nil {
			t.Fatalf("keeping only %d of 3 chunks must fail", k)
		}
	}
}

func TestCipherV2TruncationAtEveryLength(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(70), sec("pw"))
	for n := 0; n < len(enc); n++ {
		if _, err := tinyV2().Decrypt(enc[:n], sec("pw")); err == nil {
			t.Fatalf("truncation to %d of %d bytes should fail", n, len(enc))
		}
	}
}

func TestV1TruncationAtEveryLength(t *testing.T) {
	enc, _ := NewCipherV1().Encrypt([]byte("data"), sec("pw"))
	for n := 0; n < len(enc); n++ {
		if _, err := NewCipherV1().Decrypt(enc[:n], sec("pw")); err == nil {
			t.Fatalf("truncation to %d bytes should fail", n)
		}
	}
}

func TestTrailingGarbageFails(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("data"), sec("pw"))
			for _, extra := range [][]byte{{0xFF}, make([]byte, 16), make([]byte, 40)} {
				if _, err := c.Decrypt(append(append([]byte(nil), enc...), extra...), sec("pw")); err == nil {
					t.Fatalf("appending %d bytes should fail", len(extra))
				}
			}
		})
	}
}

// Every single byte of a V2 file is authenticated (the version byte is
// checked on parse; the rest by the header AAD, the nonce and the tags).
func TestCipherV2BitFlipAnywhereDetected(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(40), sec("pw"))
	for i := range enc {
		for _, bit := range []byte{0x01, 0x80} {
			mutated := append([]byte(nil), enc...)
			mutated[i] ^= bit
			if _, err := tinyV2().Decrypt(mutated, sec("pw")); err == nil {
				t.Fatalf("flip of 0x%02x at byte %d not detected", bit, i)
			}
		}
	}
}

// V1 only routes on the version byte, so flips after it must be detected.
func TestCipherV1BitFlipDetected(t *testing.T) {
	enc, _ := NewCipherV1().Encrypt([]byte("tamper me"), sec("pw"))
	for i := 1; i < len(enc); i++ {
		mutated := append([]byte(nil), enc...)
		mutated[i] ^= 0x01
		if _, err := NewCipherV1().Decrypt(mutated, sec("pw")); err == nil {
			t.Fatalf("flip at byte %d not detected", i)
		}
	}
}

func TestCrossVersionDecryptFails(t *testing.T) {
	v1, v2 := NewCipherV1(), fastV2()
	e1, _ := v1.Encrypt([]byte("data"), sec("pw"))
	e2, _ := v2.Encrypt([]byte("data"), sec("pw"))
	if _, err := v2.Decrypt(e1, sec("pw")); err == nil {
		t.Fatal("V2 must not decrypt V1 data")
	}
	if _, err := v1.Decrypt(e2, sec("pw")); err == nil {
		t.Fatal("V1 must not decrypt V2 data")
	}
}

// ----------------------------------------------------------------------------
// Key file
// ----------------------------------------------------------------------------

func TestKeyFileRoundTripAndRequirements(t *testing.T) {
	c := fastV2()
	enc, err := c.Encrypt([]byte("secret"), secKF("pw", "kf-one"))
	if err != nil {
		t.Fatal(err)
	}

	if dec, err := c.Decrypt(enc, secKF("pw", "kf-one")); err != nil || string(dec) != "secret" {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := c.Decrypt(enc, sec("pw")); err == nil || !strings.Contains(err.Error(), "requires a key file") {
		t.Fatalf("missing key file: %v", err)
	}
	if _, err := c.Decrypt(enc, secKF("pw", "kf-two")); err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("wrong key file: %v", err)
	}
	if _, err := c.Decrypt(enc, secKF("other", "kf-one")); err == nil {
		t.Fatal("wrong password with right key file must fail")
	}
}

func TestKeyFileNotAcceptedForFilesWithoutOne(t *testing.T) {
	c := fastV2()
	enc, _ := c.Encrypt([]byte("secret"), sec("pw"))
	if _, err := c.Decrypt(enc, secKF("pw", "kf")); err == nil || !strings.Contains(err.Error(), "not encrypted with a key file") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestKeyFileFlagCannotBeStripped(t *testing.T) {
	c := fastV2()
	enc, _ := c.Encrypt([]byte("secret"), secKF("pw", "kf"))
	enc[1] = 0 // pretend no key file is needed
	if _, err := c.Decrypt(enc, sec("pw")); err == nil {
		t.Fatal("clearing the flag must not allow decryption")
	}
}

func TestKeyFileIsPartOfTheKey(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltSizeV2)
	h := headerV2{chunkLog2: 6, kdf: fastKDF}
	copy(h.salt[:], salt)
	a, _ := newAEADV2(h, sec("pw"))
	b, _ := newAEADV2(h, secKF("pw", "kf"))
	c, _ := newAEADV2(h, secKF("pw", "kf2"))
	nonce := make([]byte, NonceSize)
	sa, sb, sc := a.Seal(nil, nonce, []byte("x"), nil), b.Seal(nil, nonce, []byte("x"), nil), c.Seal(nil, nonce, []byte("x"), nil)
	if bytes.Equal(sa, sb) || bytes.Equal(sb, sc) || bytes.Equal(sa, sc) {
		t.Fatal("password, password+keyfile and password+other keyfile must derive different keys")
	}
}

func TestEmptyKeyFileIsIgnored(t *testing.T) {
	c := fastV2()
	enc, err := c.Encrypt([]byte("x"), Secret{Password: []byte("pw"), KeyFile: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if enc[1] != 0 {
		t.Fatal("an empty key file must not set the flag")
	}
}

func TestV1RejectsKeyFiles(t *testing.T) {
	v1 := NewCipherV1()
	if _, err := v1.Encrypt([]byte("x"), secKF("pw", "kf")); err == nil {
		t.Fatal("V1 encrypt must reject key files")
	}
	enc, _ := v1.Encrypt([]byte("x"), sec("pw"))
	if _, err := v1.Decrypt(enc, secKF("pw", "kf")); err == nil {
		t.Fatal("V1 decrypt must reject key files")
	}
}

func TestSecretMaterialAndWipe(t *testing.T) {
	s := sec("pw")
	if !bytes.Equal(s.material(), []byte("pw")) {
		t.Fatal("without key file the material is the password")
	}
	s = secKF("pw", "kf")
	m := s.material()
	if len(m) != 2+32 || !bytes.HasPrefix(m, []byte("pw")) {
		t.Fatalf("material = %x", m)
	}
	m[0] = 'X'
	if s.Password[0] != 'p' {
		t.Fatal("material must be a copy when a key file is present")
	}

	s.Wipe()
	if !bytes.Equal(s.Password, []byte{0, 0}) || !bytes.Equal(s.KeyFile, []byte{0, 0}) {
		t.Fatal("Wipe must zero both buffers")
	}
}

// ----------------------------------------------------------------------------
// Golden vectors
// ----------------------------------------------------------------------------

func TestGoldenWrongSecretFails(t *testing.T) {
	m := fastManager()
	for name, h := range map[string]string{
		"v1": testvectors.V1Hex, "v2": testvectors.V2Hex, "multi": testvectors.V2MultiHex, "boundary": testvectors.V2BoundaryHex,
	} {
		data := mustHex(t, h)
		c, _ := m.getCipher(data[0])
		if _, err := c.Decrypt(data, sec("nope")); err == nil {
			t.Fatalf("%s: wrong password must fail", name)
		}
	}
}

// ----------------------------------------------------------------------------
// Streaming
// ----------------------------------------------------------------------------

func TestStreamRoundTrip(t *testing.T) {
	c := tinyV2()
	pt := pattern(1000)
	var enc, dec bytes.Buffer
	if err := c.EncryptStream(&enc, bytes.NewReader(pt), sec("pw")); err != nil {
		t.Fatal(err)
	}
	if err := c.DecryptStream(&dec, &enc, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), pt) {
		t.Fatal("mismatch")
	}
}

// Readers that return a few bytes at a time must not change the output size
// or confuse the chunk and end-of-file detection.
func TestStreamHandlesTrickleReaders(t *testing.T) {
	for _, n := range []int{0, 1, 16, 17, 32, 100} {
		pt := pattern(n)
		var enc bytes.Buffer
		if err := tinyV2().EncryptStream(&enc, trickle{bytes.NewReader(pt)}, sec("pw")); err != nil {
			t.Fatal(err)
		}
		var dec bytes.Buffer
		if err := tinyV2().DecryptStream(&dec, trickle{bytes.NewReader(enc.Bytes())}, sec("pw")); err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(dec.Bytes(), pt) {
			t.Fatalf("n=%d: mismatch", n)
		}
	}
}

type trickle struct{ r io.Reader }

func (t trickle) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return t.r.Read(p)
}

func TestStreamEncryptWriteErrors(t *testing.T) {
	// fail while writing the header, the first chunk and a later chunk
	for _, after := range []int{0, headerSizeV2 - 1, headerSizeV2, headerSizeV2 + 40} {
		err := tinyV2().EncryptStream(&errWriter{left: after}, bytes.NewReader(pattern(200)), sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to write output") {
			t.Fatalf("after=%d: unexpected error: %v", after, err)
		}
	}
}

func TestStreamEncryptReadError(t *testing.T) {
	boom := io.ErrClosedPipe
	for _, n := range []int{0, 5, 16, 40} {
		err := tinyV2().EncryptStream(io.Discard, &errReader{data: pattern(n), err: boom}, sec("pw"))
		if err == nil || !strings.Contains(err.Error(), "failed to read input") {
			t.Fatalf("n=%d: unexpected error: %v", n, err)
		}
	}
}

func TestStreamDecryptWriteError(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(200), sec("pw"))
	err := tinyV2().DecryptStream(&errWriter{left: 20}, bytes.NewReader(enc), sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "failed to write output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStreamDecryptReadError(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(200), sec("pw"))
	for _, cut := range []int{5, headerSizeV2, headerSizeV2 + 20, len(enc) - 3} {
		err := tinyV2().DecryptStream(io.Discard, &errReader{data: enc[:cut], err: io.ErrClosedPipe}, sec("pw"))
		if err == nil {
			t.Fatalf("cut=%d: expected error", cut)
		}
	}
}

// No plaintext may be released before its chunk authenticated.
func TestStreamDecryptNeverEmitsUnauthenticatedData(t *testing.T) {
	enc, _ := tinyV2().Encrypt(pattern(100), sec("pw"))
	enc[headerSizeV2+3] ^= 0x01 // corrupt the very first chunk
	var out bytes.Buffer
	if err := tinyV2().DecryptStream(&out, bytes.NewReader(enc), sec("pw")); err == nil {
		t.Fatal("expected error")
	}
	if out.Len() != 0 {
		t.Fatalf("%d plaintext bytes leaked from a corrupt first chunk", out.Len())
	}
}

// Encrypting a large input must use bounded memory.
func TestStreamingUsesBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("large stream skipped in short mode")
	}
	const size = 64 << 20
	c := newCipherV2With(fastKDF, DefaultChunkLog2)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var enc countingWriter
	if err := c.EncryptStream(&enc, io.LimitReader(zeroReader{}, size), sec("pw")); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)

	if enc.n < size {
		t.Fatalf("wrote %d bytes", enc.n)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("allocated %d MiB while encrypting %d MiB", grew>>20, size>>20)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

// ----------------------------------------------------------------------------
// Inspect
// ----------------------------------------------------------------------------

func TestInspect(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		enc, _ := NewCipherV1().Encrypt([]byte("x"), sec("pw"))
		info, err := NewCipherV1().Inspect(bytes.NewReader(enc))
		if err != nil || info.Version != 1 || !info.Legacy || info.KeyFile || info.ChunkSize != 0 {
			t.Fatalf("%+v, %v", info, err)
		}
	})
	t.Run("v2", func(t *testing.T) {
		enc, _ := newCipherV2With(KDFParams{Time: 2, MemoryKiB: 2048, Threads: 3}, 12).Encrypt([]byte("x"), sec("pw"))
		info, err := NewCipherV2().Inspect(bytes.NewReader(enc))
		if err != nil || info.Version != 2 || info.Legacy || info.KeyFile || info.ChunkSize != 4096 {
			t.Fatalf("%+v, %v", info, err)
		}
		for _, want := range []string{"Argon2id", "time=2", "memory=2 MiB", "threads=3"} {
			if !strings.Contains(info.KDF, want) {
				t.Fatalf("KDF %q lacks %q", info.KDF, want)
			}
		}
	})
	t.Run("v2 key file", func(t *testing.T) {
		enc, _ := fastV2().Encrypt([]byte("x"), secKF("pw", "kf"))
		info, err := NewCipherV2().Inspect(bytes.NewReader(enc))
		if err != nil || !info.KeyFile {
			t.Fatalf("%+v, %v", info, err)
		}
	})
	t.Run("only reads the header", func(t *testing.T) {
		enc, _ := fastV2().Encrypt([]byte("x"), sec("pw"))
		if _, err := NewCipherV2().Inspect(bytes.NewReader(enc[:headerSizeV2])); err != nil {
			t.Fatalf("header alone must be enough: %v", err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		if _, err := NewCipherV2().Inspect(bytes.NewReader([]byte{2, 0, 0})); err == nil {
			t.Fatal("short v2 header")
		}
		if _, err := NewCipherV1().Inspect(bytes.NewReader([]byte{1, 0})); err == nil {
			t.Fatal("short v1 header")
		}
		if _, err := NewCipherV1().Inspect(bytes.NewReader(make([]byte, 13))); err == nil {
			t.Fatal("v1 inspect must reject a non-v1 file")
		}
		if _, err := NewCipherV2().Inspect(bytes.NewReader(make([]byte, headerSizeV2))); err == nil {
			t.Fatal("v2 inspect must reject a non-v2 file")
		}
	})
}
