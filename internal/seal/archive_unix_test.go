//go:build unix

package seal

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEncryptDirectoryRefusesSpecialFiles(t *testing.T) {
	src := sampleTree(t)
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	err := fastManager().EncryptFile(src, "", sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "not a regular file or directory") {
		t.Fatalf("unexpected error: %v", err)
	}
	noTempLeftovers(t, filepath.Dir(src))
}
