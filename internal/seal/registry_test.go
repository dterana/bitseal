package seal

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/dterana/casemate/internal/testvectors"
)

// These tests are the guard rails for adding a cipher version: they fail if
// a version is registered but not wired up, has no golden vector, or is not
// the default after being added.

func TestVersionsAreSortedAndNonEmpty(t *testing.T) {
	v := Versions()
	if len(v) == 0 {
		t.Fatal("no cipher versions registered")
	}
	for i := 1; i < len(v); i++ {
		if v[i-1] >= v[i] {
			t.Fatalf("Versions() not strictly ascending: %v", v)
		}
	}
}

func TestCurrentVersionIsRegisteredAndHighest(t *testing.T) {
	v := Versions()
	if v[len(v)-1] != CurrentVersion {
		t.Fatalf("CurrentVersion = %d but the highest registered version is %d: "+
			"a newly added version must become the default (or this check must be updated deliberately)",
			CurrentVersion, v[len(v)-1])
	}
}

func TestEveryRegisteredCipherReportsItsVersion(t *testing.T) {
	for _, v := range Versions() {
		c, ok := newCipher(v, DefaultParams)
		if !ok {
			t.Fatalf("version %d listed but not constructible", v)
		}
		if c.Version() != v {
			t.Fatalf("registered as %d but reports %d", v, c.Version())
		}
	}
}

func TestManagerWiresEveryRegisteredVersion(t *testing.T) {
	m := NewManager()
	for _, v := range Versions() {
		if _, err := m.getCipher(v); err != nil {
			t.Fatalf("version %d registered but the manager cannot route it: %v", v, err)
		}
	}
	if _, err := m.currentCipher(); err != nil {
		t.Fatalf("the current version must support streaming: %v", err)
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a version twice must panic")
		}
	}()
	register(1, func(Params) CipherVersion { return NewCipherV1() })
}

func TestUnregisteredVersionsAreRefused(t *testing.T) {
	m := NewManager()
	registered := map[byte]bool{}
	for _, v := range Versions() {
		registered[v] = true
	}
	for v := 0; v < 256; v++ {
		if registered[byte(v)] {
			continue
		}
		if _, err := m.getCipher(byte(v)); err == nil || !strings.Contains(err.Error(), "unsupported encryption version") {
			t.Fatalf("version %d should be refused, got %v", v, err)
		}
	}
}

func TestEveryRegisteredVersionHasAGoldenVector(t *testing.T) {
	have := map[byte]bool{}
	for _, v := range testvectors.All {
		have[v.Version] = true
	}
	for _, v := range Versions() {
		if !have[v] {
			t.Fatalf("cipher version %d has no golden vector in internal/testvectors", v)
		}
	}
}

func TestEveryGoldenVectorDecrypts(t *testing.T) {
	m := fastManager()
	dir := t.TempDir()
	registered := map[byte]bool{}
	for _, v := range Versions() {
		registered[v] = true
	}

	for i, v := range testvectors.All {
		t.Run(v.Name, func(t *testing.T) {
			data := mustHex(t, v.Hex)
			if data[0] != v.Version {
				t.Fatalf("vector claims version %d but starts with byte %d", v.Version, data[0])
			}
			if !registered[v.Version] {
				t.Fatalf("vector for unregistered version %d (a version must never be removed)", v.Version)
			}

			secret := Secret{Password: []byte(v.Password)}
			if v.KeyFile != "" {
				secret.KeyFile = []byte(v.KeyFile)
			}
			in := filepath.Join(dir, "v"+string(rune('a'+i))+".enc")
			out := in + ".txt"
			writeFile(t, in, data)
			if err := m.DecryptFile(in, out, secret); err != nil {
				t.Fatal(err)
			}
			if got := string(readFile(t, out)); got != v.Plaintext {
				t.Fatalf("got %q, want %q", got, v.Plaintext)
			}

			// the same file must also be readable by the inspector
			info, err := m.InspectFile(in)
			if err != nil || info.Version != v.Version {
				t.Fatalf("inspect: %+v, %v", info, err)
			}
			if wrong := (Secret{Password: []byte("not-the-password")}); true {
				if err := m.DecryptFile(in, out+".x", wrong); err == nil {
					t.Fatal("a wrong password must not decrypt a golden vector")
				}
			}
		})
	}
}
