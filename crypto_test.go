package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// Golden vectors generated with password "golden-pw" and plaintext
// "golden plaintext". They lock the on-disk formats: if these fail, old
// files would no longer decrypt.
const (
	goldenV1Hex = "014cae3ada8566a4c02117ea032a5f2e650a831777de434371b75af0e0b29aeb7e39b62311b84c8c248384d35e"
	goldenV2Hex = "02ae5e1a97da1a9ecd430402d6ca23c4c99af4ea410f3479c7059ea0dcd82d298be4051685b2bd958fcb4a7798d784124fc812761d2f3c8bbc471c9bc2"
)

func allCiphers() map[string]CipherVersion {
	return map[string]CipherVersion{
		"v1": NewCipherV1(),
		"v2": NewCipherV2(),
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

func TestCipherVersionBytes(t *testing.T) {
	if NewCipherV1().Version() != 1 || NewCipherV2().Version() != 2 {
		t.Fatal("unexpected version bytes")
	}
}

func TestRoundTrip(t *testing.T) {
	big := make([]byte, 1<<20+7)
	rand.Read(big)
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}

	plaintexts := map[string][]byte{
		"empty":       {},
		"one byte":    {0x42},
		"short text":  []byte("secret"),
		"newlines":    []byte("a\nb\r\nc\n"),
		"unicode":     []byte("héllo wörld 日本語 🔒"),
		"all bytes":   allBytes,
		"nul bytes":   {0, 0, 0, 0},
		"1 MiB+7":     big,
		"yaml secret": []byte("authtoken: abc123\nregion: eu\n"),
	}
	if testing.Short() {
		delete(plaintexts, "1 MiB+7")
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
			enc, err := c.Encrypt(pt, []byte(pw))
			if err != nil {
				t.Fatal(err)
			}
			if enc[0] != c.Version() {
				t.Fatalf("version byte = %d, want %d", enc[0], c.Version())
			}
			dec, err := c.Decrypt(enc, []byte(pw))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dec, pt) {
				t.Fatal("plaintext mismatch after round trip")
			}
		}
		// every plaintext shape with a fixed password
		for pname, pt := range plaintexts {
			t.Run(cname+"/plaintext/"+pname, func(t *testing.T) { check(t, pt, "pw") })
		}
		// every password shape with a fixed plaintext
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
			enc, err := c.Encrypt(pt, pw)
			if err != nil {
				t.Fatal(err)
			}
			encCopy := append([]byte(nil), enc...)
			if _, err := c.Decrypt(enc, pw); err != nil {
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
				if _, err := c.Encrypt([]byte("x"), pw); err == nil {
					t.Fatal("empty password should be rejected")
				}
			}
		})
	}
}

func TestWrongPasswordFails(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("secret"), []byte("right"))
			for _, bad := range []string{"wrong", "Right", "right ", " right", "righ", "rightt", ""} {
				_, err := c.Decrypt(enc, []byte(bad))
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

func TestNonceAndOutputRandomized(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			a, _ := c.Encrypt([]byte("same"), []byte("pw"))
			b, _ := c.Encrypt([]byte("same"), []byte("pw"))
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

func TestCipherV2PerFileSalt(t *testing.T) {
	c := NewCipherV2()
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		enc, err := c.Encrypt([]byte("x"), []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		salt := string(enc[1 : 1+SaltSizeV2])
		if seen[salt] {
			t.Fatal("salt reused across files")
		}
		seen[salt] = true
	}
}

func TestCipherV2DeriveKey(t *testing.T) {
	c := NewCipherV2()
	salt1 := bytes.Repeat([]byte{1}, SaltSizeV2)
	salt2 := bytes.Repeat([]byte{2}, SaltSizeV2)
	k1 := c.deriveKey([]byte("pw"), salt1)
	if len(k1) != KeySize {
		t.Fatalf("key length = %d", len(k1))
	}
	if !bytes.Equal(k1, c.deriveKey([]byte("pw"), salt1)) {
		t.Fatal("derivation must be deterministic")
	}
	if bytes.Equal(k1, c.deriveKey([]byte("pw"), salt2)) {
		t.Fatal("different salts must give different keys")
	}
	if bytes.Equal(k1, c.deriveKey([]byte("pw2"), salt1)) {
		t.Fatal("different passwords must give different keys")
	}
}

func TestCipherV2Layout(t *testing.T) {
	pt := []byte("hello")
	enc, _ := NewCipherV2().Encrypt(pt, []byte("pw"))
	want := 1 + SaltSizeV2 + NonceSize + len(pt) + 16
	if len(enc) != want {
		t.Fatalf("len = %d, want %d", len(enc), want)
	}
}

func TestCipherV1Layout(t *testing.T) {
	pt := []byte("hello")
	enc, _ := NewCipherV1().Encrypt(pt, []byte("pw"))
	want := 1 + NonceSize + len(pt) + 16
	if len(enc) != want {
		t.Fatalf("len = %d, want %d", len(enc), want)
	}
}

func TestGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		c    CipherVersion
		hex  string
	}{
		{"v1", NewCipherV1(), goldenV1Hex},
		{"v2", NewCipherV2(), goldenV2Hex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := tc.c.Decrypt(mustHex(t, tc.hex), []byte("golden-pw"))
			if err != nil {
				t.Fatal(err)
			}
			if string(dec) != "golden plaintext" {
				t.Fatalf("got %q", dec)
			}
		})
	}
}

func TestDecryptTruncatedOrTooShort(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("data"), []byte("pw"))
			// every length below the minimum is rejected before the KDF runs
			for n := 0; n < len(enc)-4; n++ {
				if n > 1+SaltSizeV2+NonceSize && n < len(enc)-8 {
					continue // past the header, sample only the boundaries
				}
				if _, err := c.Decrypt(enc[:n], []byte("pw")); err == nil {
					t.Fatalf("truncation to %d bytes should fail", n)
				}
			}
			for _, n := range []int{len(enc) - 1, len(enc) - 8} {
				if _, err := c.Decrypt(enc[:n], []byte("pw")); err == nil {
					t.Fatalf("truncation to %d bytes should fail", n)
				}
			}
		})
	}
}

func TestDecryptTrailingGarbageFails(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("data"), []byte("pw"))
			if _, err := c.Decrypt(append(enc, 0xFF), []byte("pw")); err == nil {
				t.Fatal("appended byte should fail authentication")
			}
		})
	}
}

// Flipping a bit in the nonce, salt, ciphertext or tag must be detected, except the version
// byte, which is only used for routing (covered by the manager tests).
func TestBitFlipDetected(t *testing.T) {
	for name, c := range allCiphers() {
		t.Run(name, func(t *testing.T) {
			enc, _ := c.Encrypt([]byte("tamper me"), []byte("pw"))
			header := 1 + NonceSize
			if name == "v2" {
				header += SaltSizeV2
			}
			for _, i := range []int{1, 2, header - 1, header, header + 1, len(enc) - 17, len(enc) - 16, len(enc) - 1} {
				mutated := append([]byte(nil), enc...)
				mutated[i] ^= 0x01
				if _, err := c.Decrypt(mutated, []byte("pw")); err == nil {
					t.Fatalf("flip at byte %d not detected", i)
				}
			}
		})
	}
}

func TestCipherV2VersionByteIsAuthenticated(t *testing.T) {
	c := NewCipherV2()
	enc, _ := c.Encrypt([]byte("x"), []byte("pw"))
	enc[0] = 99
	if _, err := c.Decrypt(enc, []byte("pw")); err == nil {
		t.Fatal("V2 must authenticate the version byte")
	}
}

func TestCrossVersionDecryptFails(t *testing.T) {
	v1, v2 := NewCipherV1(), NewCipherV2()
	e1, _ := v1.Encrypt([]byte("data"), []byte("pw"))
	e2, _ := v2.Encrypt([]byte("data"), []byte("pw"))
	if _, err := v2.Decrypt(e1, []byte("pw")); err == nil {
		t.Fatal("V2 must not decrypt V1 data")
	}
	if _, err := v1.Decrypt(e2, []byte("pw")); err == nil {
		t.Fatal("V1 must not decrypt V2 data")
	}
}
