// ============================================================================
// File helpers: atomic writes, temp file tracking, signal cleanup
// ============================================================================

package seal

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

// Temp files currently being written, so an interrupt can remove them.
var temps = struct {
	mu    sync.Mutex
	paths map[string]struct{}
}{paths: map[string]struct{}{}}

func trackTemp(path string) {
	temps.mu.Lock()
	defer temps.mu.Unlock()
	temps.paths[path] = struct{}{}
}

func untrackTemp(path string) {
	temps.mu.Lock()
	defer temps.mu.Unlock()
	delete(temps.paths, path)
}

func removeTrackedTemps() {
	temps.mu.Lock()
	defer temps.mu.Unlock()
	for p := range temps.paths {
		_ = os.Remove(p) // best effort: the process is exiting
		delete(temps.paths, p)
	}
}

var signalOnce sync.Once

// InstallSignalCleanup removes in-flight temp files when the process is
// interrupted (SIGINT) or terminated (SIGTERM). SIGKILL cannot be caught.
func InstallSignalCleanup() {
	signalOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		go func() {
			sig := <-ch
			removeTrackedTemps()
			if sig == os.Interrupt {
				os.Exit(130)
			}
			os.Exit(143)
		}()
	})
}

// writeAtomicWith streams fn's output into a temp file in the destination
// directory and renames it into place, so a failed run never truncates or
// half-writes an existing file. Errors from fn are returned unchanged.
func writeAtomicWith(path string, perm os.FileMode, fn func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".casemate-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	name := tmp.Name()
	trackTemp(name)
	defer untrackTemp(name)

	abort := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	fsErr := func(err error) error {
		return abort(fmt.Errorf("failed to write output file: %w", err))
	}

	if err := fn(tmp); err != nil {
		return abort(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fsErr(err)
	}
	if err := tmp.Sync(); err != nil {
		return fsErr(err)
	}
	if err := tmp.Close(); err != nil {
		return fsErr(err)
	}
	if err := os.Rename(name, path); err != nil {
		return fsErr(err)
	}
	return nil
}

// writeFileAtomic writes data atomically (see writeAtomicWith).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeAtomicWith(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// samePath reports whether two paths refer to the same file, either by name
// or because the output already exists as the same file (e.g. a symlink).
func samePath(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}
