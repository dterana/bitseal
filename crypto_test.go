package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCipherV2RoundTrip(t *testing.T) {
	c := NewCipherV2()
	enc, err := c.Encrypt([]byte("secret"), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 2 {
		t.Fatalf("version byte = %d", enc[0])
	}
	dec, err := c.Decrypt(enc, []byte("pw"))
	if err != nil || string(dec) != "secret" {
		t.Fatalf("got %q, %v", dec, err)
	}
	if _, err := c.Decrypt(enc, []byte("bad")); err == nil {
		t.Fatal("wrong password should fail")
	}
}

func TestCipherV2PerFileSalt(t *testing.T) {
	c := NewCipherV2()
	a, _ := c.Encrypt([]byte("x"), []byte("pw"))
	b, _ := c.Encrypt([]byte("x"), []byte("pw"))
	if bytes.Equal(a[1:17], b[1:17]) {
		t.Fatal("salts must differ per file")
	}
}

func TestCipherV2HeaderTamper(t *testing.T) {
	c := NewCipherV2()
	enc, _ := c.Encrypt([]byte("x"), []byte("pw"))
	enc[5] ^= 1 // flip a salt bit
	if _, err := c.Decrypt(enc, []byte("pw")); err == nil {
		t.Fatal("tampered salt should fail")
	}
}

func TestV1FilesStillDecrypt(t *testing.T) {
	enc, err := NewCipherV1().Encrypt([]byte("legacy"), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "a.enc")
	out := filepath.Join(dir, "a")
	os.WriteFile(in, enc, 0600)
	if err := NewCipherManager().DecryptFile(in, out, "pw"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "legacy" {
		t.Fatalf("got %q", got)
	}
}

func TestEncryptFileUsesV2(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "a")
	os.WriteFile(in, []byte("hello"), 0600)
	m := NewCipherManager()
	if err := m.EncryptFile(in, "", "pw"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(in + ".enc")
	if data[0] != 2 {
		t.Fatalf("version = %d", data[0])
	}
	out := filepath.Join(dir, "b")
	if err := m.DecryptFile(in+".enc", out, "pw"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}
