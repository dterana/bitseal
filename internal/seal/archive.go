// ============================================================================
// Directory archives: a tar stream encrypted like any other file
// ============================================================================

package seal

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveSuffix ends the default name of an encrypted directory archive. The
// content is an ordinary tar stream inside a normal encrypted file, so the
// file format is unchanged and any version can read it back with `decrypt`.
const ArchiveSuffix = ".tar.enc"

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// pipeThrough runs produce in a goroutine that writes into a pipe, and
// consume on the reading end. It returns the most meaningful error of the two.
func pipeThrough(produce func(io.Writer) error, consume func(io.Reader) error) error {
	pr, pw := io.Pipe()
	prodErrc := make(chan error, 1)
	go func() {
		err := produce(pw)
		_ = pw.CloseWithError(err)
		prodErrc <- err
	}()

	consErr := consume(pr)
	_ = pr.CloseWithError(consErr)
	prodErr := <-prodErrc

	switch {
	case consErr == nil:
		return prodErr
	case prodErr == nil:
		return consErr
	case errors.Is(consErr, prodErr):
		return prodErr // the consumer only reported the producer's failure
	default:
		return consErr
	}
}

// ----------------------------------------------------------------------------
// Encrypting a directory
// ----------------------------------------------------------------------------

func (m *Manager) encryptDir(dir, outputPath string, secret Secret) error {
	sc, err := m.currentCipher()
	if err != nil {
		return err
	}
	switch filepath.Base(filepath.Clean(dir)) {
	case ".", "..", string(filepath.Separator):
		if outputPath == "" {
			return fmt.Errorf("cannot name the archive of %q: use -out", dir)
		}
	}
	// The user named this directory, so a symlink to a directory is followed
	// at the top level only. Links inside it are refused while archiving.
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	outputPath = ResolveEncryptOut(dir, outputPath)
	if outputPath == StdioPath && m.OutIsTerminal() {
		return fmt.Errorf("refusing to write encrypted data to a terminal; use -out <file> or redirect stdout")
	}
	if outputPath != StdioPath {
		if inside, err := pathInside(root, outputPath); err != nil {
			return err
		} else if inside {
			return fmt.Errorf("output path must not be inside the directory being archived")
		}
	}

	return m.writeOutput(outputPath, false, func(w io.Writer) error {
		return pipeThrough(
			func(pw io.Writer) error { return writeTar(pw, root) },
			func(pr io.Reader) error { return sc.EncryptStream(w, pr, secret) },
		)
	})
}

// pathInside reports whether path lies inside the directory root, resolving
// symlinks in the part that exists so a link cannot hide the overlap.
func pathInside(root, path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("failed to resolve output path: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return false, nil // the output directory does not exist; writing will report it
	}
	rel, err := filepath.Rel(root, filepath.Join(parent, filepath.Base(abs)))
	if err != nil {
		return false, nil
	}
	return filepath.IsLocal(rel), nil
}

// writeTar writes the tree under root as a tar stream. Only regular files and
// directories are archived; anything else is an error, so nothing is silently
// left out. Ownership is not recorded and only permission bits are kept.
func writeTar(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", rel, err)
		}

		hdr := &tar.Header{
			Name:    filepath.ToSlash(rel),
			Mode:    int64(info.Mode().Perm()),
			ModTime: info.ModTime(),
		}
		switch {
		case info.IsDir():
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			return tw.WriteHeader(hdr)
		case info.Mode().IsRegular():
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			return writeTarFile(tw, hdr, path)
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is a symbolic link, which directory archives do not support", rel)
		default:
			return fmt.Errorf("%s is not a regular file or directory, which directory archives do not support", rel)
		}
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func writeTarFile(tw *tar.Writer, hdr *tar.Header, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", hdr.Name, err)
	}
	defer func() { _ = f.Close() }()
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("failed to archive %s (did it change while reading?): %w", hdr.Name, err)
	}
	return tw.Flush()
}

// ----------------------------------------------------------------------------
// Extracting a directory
// ----------------------------------------------------------------------------

// ResolveExtractOut picks the default destination directory for extraction.
func ResolveExtractOut(in, out string) (string, error) {
	switch {
	case out != "":
		return out, nil
	case in == StdioPath:
		return "", fmt.Errorf("cannot infer output directory from stdin, use -out")
	case !strings.HasSuffix(in, ArchiveSuffix) || len(in) == len(ArchiveSuffix):
		return "", fmt.Errorf("cannot infer output directory: input does not end in %s, use -out", ArchiveSuffix)
	}
	return strings.TrimSuffix(in, ArchiveSuffix), nil
}

// ExtractFile decrypts a directory archive into destDir, which must not exist.
//
// Nothing appears at destDir until the whole file has authenticated: entries
// are unpacked into a hidden staging directory next to it, which is renamed
// into place on success and removed on any failure. Entries that are absolute,
// climb out with "..", or are anything but regular files and directories are
// refused. The extracted directory itself is created with mode 0700.
func (m *Manager) ExtractFile(inputPath, destDir string, secret Secret) error {
	src, closeSrc, err := m.openInput(inputPath)
	if err != nil {
		return err
	}
	defer closeSrc()

	destDir, err = ResolveExtractOut(inputPath, destDir)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(destDir); err == nil {
		return fmt.Errorf("%s already exists; refusing to extract into it", destDir)
	}

	c, br, err := m.openCipher(src)
	if err != nil {
		return err
	}

	stage, err := os.MkdirTemp(filepath.Dir(destDir), ".casemate-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}
	trackTemp(stage)
	defer untrackTemp(stage)
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(stage)
		}
	}()

	x := &extractor{root: stage}
	err = pipeThrough(
		func(w io.Writer) error { return decryptTo(c, w, br, secret) },
		x.untar,
	)
	if err != nil {
		return err
	}
	if err := x.applyDirModes(); err != nil {
		return err
	}
	if _, err := os.Lstat(destDir); err == nil {
		return fmt.Errorf("%s already exists; refusing to extract into it", destDir)
	}
	if err := os.Rename(stage, destDir); err != nil {
		return fmt.Errorf("failed to move extracted files into place: %w", err)
	}
	done = true
	return nil
}

type dirMode struct {
	path string
	perm os.FileMode
}

// extractor unpacks a tar stream into root.
type extractor struct {
	root string
	dirs []dirMode // archived directory modes, applied after extraction
}

func (x *extractor) untar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("not a valid directory archive: %w", err)
		}
		if err := x.entry(tr, hdr); err != nil {
			return err
		}
	}
	// The cipher only authenticates the last chunk once it has been read in
	// full, and the tar footer ends before the padding of the final chunk.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	return nil
}

func (x *extractor) entry(tr *tar.Reader, hdr *tar.Header) error {
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	name := hdr.Name
	if name == "./" || name == "." {
		return nil
	}
	if !filepath.IsLocal(filepath.FromSlash(name)) {
		return fmt.Errorf("refusing archive entry with unsafe path %q", name)
	}
	target := filepath.Join(x.root, filepath.FromSlash(name))
	perm := os.FileMode(hdr.Mode & 0o777)

	switch hdr.Typeflag {
	case tar.TypeDir:
		// Directories stay writable while files are added; the archived mode
		// is applied at the end.
		if err := os.MkdirAll(target, 0o700); err != nil {
			return fmt.Errorf("failed to create %s: %w", name, err)
		}
		x.dirs = append(x.dirs, dirMode{target, perm})
		return nil
	case tar.TypeReg:
		return x.file(tr, hdr, target, perm)
	default:
		return fmt.Errorf("refusing archive entry %q: only regular files and directories are supported", name)
	}
}

func (x *extractor) file(tr *tar.Reader, hdr *tar.Header, target string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", hdr.Name, err)
	}
	// O_EXCL: a repeated name is an error, never an overwrite.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", hdr.Name, err)
	}
	if _, err := io.Copy(f, tr); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write %s: %w", hdr.Name, err)
	}
	if err := os.Chmod(target, perm); err != nil {
		return fmt.Errorf("failed to set mode of %s: %w", hdr.Name, err)
	}
	if !hdr.ModTime.IsZero() {
		_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime) // best effort
	}
	return nil
}

// applyDirModes sets the archived modes, deepest directories first so a
// restrictive parent mode cannot block its children.
func (x *extractor) applyDirModes() error {
	for i := len(x.dirs) - 1; i >= 0; i-- {
		d := x.dirs[i]
		if err := os.Chmod(d.path, d.perm); err != nil {
			return fmt.Errorf("failed to set directory mode: %w", err)
		}
	}
	return nil
}
