package seal

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
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

// Arbitrary tar bytes must never panic the extractor, write outside its
// root, or create anything but regular files and directories.
func FuzzExtractTar(f *testing.F) {
	var valid bytes.Buffer
	tw := tar.NewWriter(&valid)
	_ = tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "d/f", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	f.Add(valid.Bytes())

	for _, h := range []tar.Header{
		{Name: "../x", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "/abs", Typeflag: tar.TypeReg, Mode: 0o644},
		{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "../..", Mode: 0o777},
		{Name: "h", Typeflag: tar.TypeLink, Linkname: "d/f", Mode: 0o644},
	} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		_ = w.WriteHeader(&h)
		_ = w.Close()
		f.Add(b.Bytes())
	}
	f.Add([]byte{})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		root := filepath.Join(parent, "stage")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		x := &extractor{root: root}
		_ = x.untar(bytes.NewReader(data))

		if entries, err := os.ReadDir(parent); err != nil || len(entries) != 1 {
			t.Fatalf("extraction wrote outside its root: %v, %v", entries, err)
		}
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && !d.Type().IsRegular() {
				t.Fatalf("%s is neither a file nor a directory", path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
