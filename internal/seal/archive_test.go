package seal

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func mkdirs(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, perm); err != nil {
		t.Fatal(err)
	}
}

func chmod(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

// sampleTree builds a small tree with nesting, an empty directory, an empty
// file, a multi-chunk file and non-default modes, and returns its root.
func sampleTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "project")
	mkdirs(t, filepath.Join(root, "docs", "deep", "er"), 0o755)
	mkdirs(t, filepath.Join(root, "empty"), 0o755)
	writeFile(t, filepath.Join(root, "a.txt"), []byte("alpha"))
	writeFile(t, filepath.Join(root, "empty.txt"), nil)
	writeFile(t, filepath.Join(root, "docs", "deep", "big.bin"), pattern(5000)) // many 64 byte chunks
	writeFile(t, filepath.Join(root, "docs", "deep", "er", "z.txt"), []byte("zeta"))
	chmod(t, filepath.Join(root, "a.txt"), 0o640)
	chmod(t, filepath.Join(root, "docs", "deep"), 0o750)
	return root
}

type entry struct {
	dir  bool
	mode os.FileMode
	data string
}

// snapshot lists every path under root with its kind, mode and content.
func snapshot(t *testing.T, root string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := entry{dir: info.IsDir(), mode: info.Mode().Perm()}
		if !e.dir {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			e.data = string(b)
		}
		out[filepath.ToSlash(rel)] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unlockTree makes every directory writable again so t.TempDir can clean up.
func unlockTree(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

// evilArchive encrypts a hand-built tar stream as <dir>/evil.tar.enc.
func evilArchive(t *testing.T, build func(*tar.Writer)) (m *Manager, archive string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "evil.tar")
	writeFile(t, plain, buf.Bytes())
	m = fastManager()
	if err := m.EncryptFile(plain, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	return m, plain + ".enc"
}

func addFile(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0)}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

// assertNothingExtracted checks that a failed extraction left neither the
// destination nor a staging directory behind.
func assertNothingExtracted(t *testing.T, dest string) {
	t.Helper()
	if _, err := os.Lstat(dest); err == nil {
		t.Fatalf("destination %s exists after a failed extraction", dest)
	}
	noTempLeftovers(t, filepath.Dir(dest))
}

// ----------------------------------------------------------------------------
// round trip
// ----------------------------------------------------------------------------

func TestDirectoryRoundTrip(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()

	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	archive := src + ArchiveSuffix
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("default archive name: %v", err)
	}
	noTempLeftovers(t, filepath.Dir(src))

	dest := filepath.Join(t.TempDir(), "restored")
	t.Cleanup(func() { unlockTree(dest) })
	if err := m.ExtractFile(archive, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	noTempLeftovers(t, filepath.Dir(dest))

	want, got := snapshot(t, src), snapshot(t, dest)
	if len(want) != len(got) {
		t.Fatalf("entries: want %d, got %d", len(want), len(got))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Fatalf("%s missing after extraction", name)
		}
		if g != w {
			t.Fatalf("%s differs: want %+v, got %+v", name, summary(w), summary(g))
		}
	}
}

func summary(e entry) entry {
	if len(e.data) > 20 {
		e.data = e.data[:20] + "..."
	}
	return e
}

func TestDirectoryRoundTripKeepsRestrictiveDirectoryModes(t *testing.T) {
	src := filepath.Join(t.TempDir(), "locked")
	mkdirs(t, filepath.Join(src, "ro"), 0o755)
	writeFile(t, filepath.Join(src, "ro", "f.txt"), []byte("x"))
	chmod(t, filepath.Join(src, "ro"), 0o500)
	t.Cleanup(func() { unlockTree(src) })

	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	t.Cleanup(func() { unlockTree(dest) })
	if err := m.ExtractFile(src+ArchiveSuffix, dest, sec("pw")); err != nil {
		t.Fatalf("a read-only directory must not block its own contents: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dest, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o500 {
		t.Fatalf("directory mode %v, want 0500", fi.Mode().Perm())
	}
}

func TestExtractedRootIsPrivate(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := m.ExtractFile(src+ArchiveSuffix, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("root mode %v, want 0700", fi.Mode().Perm())
	}
}

func TestEmptyDirectoryRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "nothing")
	mkdirs(t, src, 0o755)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := m.ExtractFile(src+ArchiveSuffix, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if got := snapshot(t, dest); len(got) != 0 {
		t.Fatalf("expected an empty directory, got %v", got)
	}
}

func TestArchiveIsPlainEncryptedTar(t *testing.T) {
	// Any version can read the archive back with an ordinary decrypt: the
	// file format did not change.
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	info, err := m.InspectFile(src + ArchiveSuffix)
	if err != nil || info.Version != CurrentVersion {
		t.Fatalf("info: %+v, %v", info, err)
	}
	tarPath := filepath.Join(t.TempDir(), "plain.tar")
	if err := m.DecryptFile(src+ArchiveSuffix, tarPath, sec("pw")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "..") {
			t.Fatalf("unsafe name written: %q", h.Name)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Fatalf("ownership must not be recorded: %+v", h)
		}
		names = append(names, h.Name)
	}
	if len(names) != len(snapshot(t, src)) {
		t.Fatalf("tar has %d entries: %v", len(names), names)
	}
}

func TestExtractFromStdin(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, src+ArchiveSuffix)

	sm, _ := stdioManager(string(data))
	dest := filepath.Join(t.TempDir(), "out")
	if err := sm.ExtractFile(StdioPath, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, filepath.Join(dest, "a.txt"))) != "alpha" {
		t.Fatal("content differs")
	}

	sm, _ = stdioManager(string(data))
	if err := sm.ExtractFile(StdioPath, "", sec("pw")); err == nil || !strings.Contains(err.Error(), "use -out") {
		t.Fatalf("stdin without -out must ask for it: %v", err)
	}
}

// ----------------------------------------------------------------------------
// names
// ----------------------------------------------------------------------------

func TestArchiveNames(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "project")
	mkdirs(t, sub, 0o755)

	if got := ResolveEncryptOut(sub, ""); got != sub+".tar.enc" {
		t.Fatalf("got %q", got)
	}
	if got := ResolveEncryptOut(sub+string(filepath.Separator), ""); got != sub+".tar.enc" {
		t.Fatalf("trailing separator: got %q", got)
	}
	if got := ResolveEncryptOut(sub, "x.bin"); got != "x.bin" {
		t.Fatalf("explicit -out wins: got %q", got)
	}
	if got := ResolveEncryptOut(filepath.Join(dir, "plain.txt"), ""); got != filepath.Join(dir, "plain.txt")+".enc" {
		t.Fatalf("files keep .enc: got %q", got)
	}

	cases := []struct {
		in, out, want string
		wantErr       string
	}{
		{"project.tar.enc", "", "project", ""},
		{"a/b/project.tar.enc", "", "a/b/project", ""},
		{"project.tar.enc", "elsewhere", "elsewhere", ""},
		{"project.enc", "", "", "does not end in .tar.enc"},
		{".tar.enc", "", "", "does not end in .tar.enc"},
		{"-", "", "", "use -out"},
	}
	for _, tc := range cases {
		got, err := ResolveExtractOut(tc.in, tc.out)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%q: error %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %q, %v, want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestEncryptCurrentDirectoryNeedsOut(t *testing.T) {
	src := sampleTree(t)
	t.Chdir(src)
	m := fastManager()
	err := m.EncryptFile(".", "", sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "use -out") {
		t.Fatalf("unexpected error: %v", err)
	}
	out := filepath.Join(t.TempDir(), "here.tar.enc")
	if err := m.EncryptFile(".", out, sec("pw")); err != nil {
		t.Fatal(err)
	}
}

// ----------------------------------------------------------------------------
// refusing what cannot be archived
// ----------------------------------------------------------------------------

func TestEncryptDirectoryRefusesSymlinks(t *testing.T) {
	src := sampleTree(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	m := fastManager()
	err := m.EncryptFile(src, "", sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") || !strings.Contains(err.Error(), "link") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(src + ArchiveSuffix); err == nil {
		t.Fatal("a failed archive must not leave an output file")
	}
	noTempLeftovers(t, filepath.Dir(src))
}

func TestEncryptDirectoryFollowsASymlinkedRoot(t *testing.T) {
	src := sampleTree(t)
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(src, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	m := fastManager()
	if err := m.EncryptFile(link, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	if err := m.ExtractFile(link+ArchiveSuffix, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, filepath.Join(dest, "a.txt"))) != "alpha" {
		t.Fatal("content differs")
	}
}

func TestEncryptDirectoryRefusesOutputInsideIt(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	inside := filepath.Join(src, "docs", "out.tar.enc")
	err := m.EncryptFile(src, inside, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "inside the directory") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(inside); err == nil {
		t.Fatal("output was written anyway")
	}
}

func TestEncryptDirectoryToStdout(t *testing.T) {
	src := sampleTree(t)
	m, out := stdioManager("")
	if err := m.EncryptFile(src, StdioPath, sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	sm, _ := stdioManager(out.String())
	if err := sm.ExtractFile(StdioPath, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, filepath.Join(dest, "docs", "deep", "er", "z.txt"))) != "zeta" {
		t.Fatal("content differs")
	}

	m, _ = stdioManager("")
	m.OutIsTerminal = func() bool { return true }
	if err := m.EncryptFile(src, StdioPath, sec("pw")); err == nil {
		t.Fatal("must refuse to write to a terminal")
	}
}

// ----------------------------------------------------------------------------
// hostile archives: nothing may appear, nothing may escape
// ----------------------------------------------------------------------------

func TestExtractRefusesUnsafeEntries(t *testing.T) {
	cases := map[string]struct {
		build func(t *testing.T, tw *tar.Writer)
		want  string
	}{
		"absolute path": {func(t *testing.T, tw *tar.Writer) { addFile(t, tw, "/tmp/casemate-escape", "x") }, "unsafe path"},
		"parent escape": {func(t *testing.T, tw *tar.Writer) { addFile(t, tw, "../casemate-escape", "x") }, "unsafe path"},
		"nested escape": {func(t *testing.T, tw *tar.Writer) { addFile(t, tw, "a/../../casemate-escape", "x") }, "unsafe path"},
		"escaping dir": {func(t *testing.T, tw *tar.Writer) {
			if err := tw.WriteHeader(&tar.Header{Name: "../x/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				t.Fatal(err)
			}
		}, "unsafe path"},
		"symlink": {func(t *testing.T, tw *tar.Writer) {
			if err := tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc", Mode: 0o777}); err != nil {
				t.Fatal(err)
			}
		}, "only regular files and directories"},
		"hard link": {func(t *testing.T, tw *tar.Writer) {
			addFile(t, tw, "f", "x")
			if err := tw.WriteHeader(&tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "f", Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
		}, "only regular files and directories"},
		"device": {func(t *testing.T, tw *tar.Writer) {
			if err := tw.WriteHeader(&tar.Header{Name: "d", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3, Mode: 0o666}); err != nil {
				t.Fatal(err)
			}
		}, "only regular files and directories"},
		"duplicate file": {func(t *testing.T, tw *tar.Writer) {
			addFile(t, tw, "dup", "one")
			addFile(t, tw, "dup", "two")
		}, "failed to create dup"},
		"file over directory": {func(t *testing.T, tw *tar.Writer) {
			if err := tw.WriteHeader(&tar.Header{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				t.Fatal(err)
			}
			addFile(t, tw, "d", "x")
		}, "failed to create d"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m, archive := evilArchive(t, func(tw *tar.Writer) { tc.build(t, tw) })
			parent := t.TempDir()
			dest := filepath.Join(parent, "out")

			err := m.ExtractFile(archive, dest, sec("pw"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			assertNothingExtracted(t, dest)
			for _, escaped := range []string{
				filepath.Join(parent, "casemate-escape"),
				filepath.Join(filepath.Dir(parent), "casemate-escape"),
				"/tmp/casemate-escape",
			} {
				if _, err := os.Lstat(escaped); err == nil {
					t.Fatalf("%s was created outside the destination", escaped)
				}
			}
		})
	}
}

func TestExtractWrongPasswordLeavesNothing(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	err := m.ExtractFile(src+ArchiveSuffix, dest, sec("wrong"))
	if err == nil || !strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNothingExtracted(t, dest)
}

func TestExtractTruncatedArchiveLeavesNothing(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, src+ArchiveSuffix)

	// Cut at several points, including exactly on chunk boundaries (64 byte
	// chunks plus 16 byte tags after the 35 byte header).
	for _, cut := range []int{len(data) - 1, len(data) - 80, 35 + 80, 35 + 2*80, len(data) / 2} {
		trunc := filepath.Join(t.TempDir(), "cut.tar.enc")
		writeFile(t, trunc, data[:cut])
		dest := filepath.Join(t.TempDir(), "out")
		if err := m.ExtractFile(trunc, dest, sec("pw")); err == nil {
			t.Fatalf("cut at %d: truncated archive extracted without error", cut)
		}
		assertNothingExtracted(t, dest)
	}
}

func TestExtractTamperedArchiveLeavesNothing(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	data := readFile(t, src+ArchiveSuffix)
	data[len(data)-30] ^= 0xff
	bad := filepath.Join(t.TempDir(), "bad.tar.enc")
	writeFile(t, bad, data)
	dest := filepath.Join(t.TempDir(), "out")
	if err := m.ExtractFile(bad, dest, sec("pw")); err == nil {
		t.Fatal("tampered archive extracted without error")
	}
	assertNothingExtracted(t, dest)
}

func TestExtractRejectsFileThatIsNotAnArchive(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "notes.txt")
	writeFile(t, plain, bytes.Repeat([]byte("just some text, not a tar stream. "), 40))
	m := fastManager()
	if err := m.EncryptFile(plain, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	err := m.ExtractFile(plain+".enc", dest, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "not a valid directory archive") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNothingExtracted(t, dest)
}

func TestExtractNeverTouchesAnExistingDestination(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	mkdirs(t, dest, 0o755)
	keep := filepath.Join(dest, "keep.txt")
	writeFile(t, keep, []byte("mine"))

	err := m.ExtractFile(src+ArchiveSuffix, dest, sec("pw"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(readFile(t, keep)) != "mine" || len(snapshot(t, dest)) != 1 {
		t.Fatal("existing destination was modified")
	}
	noTempLeftovers(t, filepath.Dir(dest))

	// a file or a dangling symlink at the destination counts as existing too
	asFile := filepath.Join(t.TempDir(), "out")
	writeFile(t, asFile, []byte("file"))
	if err := m.ExtractFile(src+ArchiveSuffix, asFile, sec("pw")); err == nil {
		t.Fatal("extracted over a file")
	}
	dangling := filepath.Join(t.TempDir(), "out")
	if err := os.Symlink(filepath.Join(t.TempDir(), "nowhere"), dangling); err == nil {
		if err := m.ExtractFile(src+ArchiveSuffix, dangling, sec("pw")); err == nil {
			t.Fatal("extracted through a dangling symlink")
		}
	}
}

func TestExtractIntoMissingParentFails(t *testing.T) {
	src := sampleTree(t)
	m := fastManager()
	if err := m.EncryptFile(src, "", sec("pw")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "no", "such", "parent")
	if err := m.ExtractFile(src+ArchiveSuffix, dest, sec("pw")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestExtractLegacyV1ArchiveIsNotSpecial(t *testing.T) {
	// A V1 file holding a tar still extracts: the archive layer sits on top
	// of whatever cipher version wrote the file.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	addFile(t, tw, "v1.txt", "legacy")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	enc, err := NewCipherV1().Encrypt(buf.Bytes(), sec("pw"))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "old.tar.enc")
	writeFile(t, archive, enc)

	dest := filepath.Join(t.TempDir(), "out")
	if err := fastManager().ExtractFile(archive, dest, sec("pw")); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, filepath.Join(dest, "v1.txt"))) != "legacy" {
		t.Fatal("content differs")
	}
}
