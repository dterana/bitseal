package seal

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dterana/casemate/internal/testvectors"
)

// The promise in the changelog is that a new version never loses the ability
// to read files written by an earlier one. This test keeps it: for every
// released tag it reads the golden vectors as they were at that tag and
// decrypts them with the current code.
//
// It needs the tags in the local clone. Without git or tags (a source
// tarball, a shallow clone) it skips; CI fetches the full history.

var vectorConst = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*"([^"]*)"`)

func releasedTags(t *testing.T) []string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	out, err := exec.Command("git", "tag", "--list", "v*").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	tags := strings.Fields(string(out))
	if len(tags) == 0 {
		t.Skip("no release tags in this clone (shallow checkout?)")
	}
	return tags
}

// vectorsAt returns the string constants of internal/testvectors/vectors.go
// as they were at the tag.
func vectorsAt(t *testing.T, tag string) map[string]string {
	t.Helper()
	out, err := exec.Command("git", "show", tag+":internal/testvectors/vectors.go").Output()
	if err != nil {
		t.Skipf("%s has no golden vectors file: %v", tag, err)
	}
	consts := map[string]string{}
	for _, m := range vectorConst.FindAllStringSubmatch(string(out), -1) {
		consts[m[1]] = m[2]
	}
	return consts
}

// plaintextFor maps a vector constant to the plaintext it must decrypt to and
// whether it needs the key file. A new kind of vector has to be added here, so
// the test never silently skips one.
func plaintextFor(t *testing.T, tag, name string, consts map[string]string) (plaintext string, keyFile bool) {
	t.Helper()
	pick := "Plaintext"
	switch {
	case strings.Contains(name, "Multi"):
		pick = "MultiPlaintext"
	case strings.Contains(name, "Boundary"):
		pick = "BoundaryPlaintext"
	}
	plaintext, ok := consts[pick]
	if !ok {
		t.Fatalf("%s: no %s constant for vector %s; teach plaintextFor about it", tag, pick, name)
	}
	return plaintext, strings.Contains(name, "KeyFile")
}

func TestReleasedTagVectorsStillDecrypt(t *testing.T) {
	current := map[string]bool{}
	for _, v := range testvectors.All {
		current[v.Hex] = true
	}
	m := fastManager()
	dir := t.TempDir()

	for _, tag := range releasedTags(t) {
		t.Run(tag, func(t *testing.T) {
			consts := vectorsAt(t, tag)
			password := consts["Password"]
			if password == "" {
				t.Fatalf("%s: no Password constant in the vectors file", tag)
			}
			n := 0
			for name, hex := range consts {
				if !strings.HasSuffix(name, "Hex") {
					continue
				}
				n++
				t.Run(name, func(t *testing.T) {
					want, needsKey := plaintextFor(t, tag, name, consts)
					secret := Secret{Password: []byte(password)}
					if needsKey {
						secret.KeyFile = []byte(consts["KeyFile"])
					}
					in := filepath.Join(dir, tag+"-"+name+".enc")
					out := in + ".txt"
					writeFile(t, in, mustHex(t, hex))
					if err := m.DecryptFile(in, out, secret); err != nil {
						t.Fatalf("a file written by %s no longer decrypts: %v", tag, err)
					}
					if got := string(readFile(t, out)); got != want {
						t.Fatalf("%s: got %q, want %q", tag, got, want)
					}
					if !current[hex] {
						t.Fatalf("vector %s of %s is gone from internal/testvectors; vectors are never removed or regenerated", name, tag)
					}
				})
			}
			if n == 0 {
				t.Fatalf("%s: found no vectors, the parser may be out of date", tag)
			}
		})
	}
}
