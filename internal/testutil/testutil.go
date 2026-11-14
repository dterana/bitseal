// Package testutil holds small helpers shared by the test suites.
package testutil

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Pattern returns n deterministic, non-repeating-looking bytes.
func Pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func MustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func WriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TempLeftovers lists Bitseal temp files in dir.
func TempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".bitseal-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// NoTempLeftovers fails the test if Bitseal temp files remain in dir.
func NoTempLeftovers(t *testing.T, dir string) {
	t.Helper()
	if l := TempLeftovers(t, dir); len(l) != 0 {
		t.Fatalf("temp files left behind: %v", l)
	}
}
