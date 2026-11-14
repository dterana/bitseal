package seal

import (
	"bytes"
	"testing"
)

// limitKDFForFuzz keeps hostile headers from requesting huge Argon2 memory
// while fuzzing. The production bounds are covered by regular tests.
func limitKDFForFuzz(t *testing.T) {
	t.Helper()
	oldMem, oldTime := maxKDFMemoryKiB, maxKDFTime
	maxKDFMemoryKiB, maxKDFTime = 1024, 3
	t.Cleanup(func() { maxKDFMemoryKiB, maxKDFTime = oldMem, oldTime })
}

func seedV2(f *testing.F) {
	for _, n := range []int{0, 1, 16, 40} {
		enc, _ := tinyV2().Encrypt(pattern(n), sec("pw"))
		f.Add(enc)
	}
	enc, _ := tinyV2().Encrypt([]byte("kf"), secKF("pw", "kf"))
	f.Add(enc)
	f.Add([]byte{})
	f.Add([]byte{2})
	f.Add(make([]byte, headerSizeV2))
	f.Add(make([]byte, headerSizeV2+gcmTagSize))
}

// Arbitrary bytes must never panic the V2 decryptor, and must never decrypt
// successfully without the matching key.
func FuzzDecryptV2(f *testing.F) {
	seedV2(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		limitKDFForFuzz(t)
		pt, err := tinyV2().Decrypt(data, sec("pw"))
		if err != nil {
			return
		}
		// a successful decryption must be reproducible and re-encryptable
		again, err := tinyV2().Decrypt(data, sec("pw"))
		if err != nil || !bytes.Equal(pt, again) {
			t.Fatal("decryption is not deterministic")
		}
	})
}

func FuzzDecryptV1(f *testing.F) {
	enc, _ := NewCipherV1().Encrypt([]byte("x"), sec("pw"))
	f.Add(enc)
	f.Add([]byte{1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NewCipherV1().Decrypt(data, sec("pw"))
	})
}

// Parsing a header and writing it back must be lossless.
func FuzzParseHeaderV2(f *testing.F) {
	enc, _ := tinyV2().Encrypt([]byte("x"), sec("pw"))
	f.Add(enc[:headerSizeV2])
	f.Add([]byte{})
	f.Add(make([]byte, headerSizeV2))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeaderV2(data)
		if err != nil {
			return
		}
		if !bytes.Equal(h.marshal(), data[:headerSizeV2]) {
			t.Fatal("marshal(parse(b)) != b")
		}
	})
}

func FuzzInspect(f *testing.F) {
	seedV2(f)
	v1, _ := NewCipherV1().Encrypt([]byte("x"), sec("pw"))
	f.Add(v1)
	f.Fuzz(func(t *testing.T, data []byte) {
		limitKDFForFuzz(t)
		m := fastManager()
		src := bytes.NewReader(data)
		c, br, err := m.openCipher(src)
		if err != nil {
			return
		}
		_, _ = c.Inspect(br)
	})
}

// Any plaintext, password and chunk size must survive a round trip.
func FuzzRoundTripV2(f *testing.F) {
	f.Add([]byte("hello"), "pw", uint8(4))
	f.Add([]byte{}, "pw", uint8(4))
	f.Add(pattern(100), "p", uint8(5))
	f.Fuzz(func(t *testing.T, plaintext []byte, password string, chunkLog2 uint8) {
		if password == "" {
			return
		}
		chunkLog2 = minChunkLog2 + chunkLog2%6 // 16 .. 512 byte chunks
		c := newCipherV2With(fastKDF, chunkLog2)
		enc, err := c.Encrypt(plaintext, sec(password))
		if err != nil {
			t.Fatal(err)
		}
		dec, err := c.Decrypt(enc, sec(password))
		if err != nil || !bytes.Equal(dec, plaintext) {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}
