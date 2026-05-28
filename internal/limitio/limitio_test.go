package limitio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
)

func TestCopyWithStrictLimitProperty(t *testing.T) {
	prop := func(data []byte, limit uint16) bool {
		maxBytes := int64(limit)
		var out bytes.Buffer
		written, err := CopyWithStrictLimit(&out, bytes.NewReader(data), maxBytes)
		if int64(out.Len()) != written {
			return false
		}
		if written > maxBytes {
			return false
		}
		if int64(len(data)) <= maxBytes {
			if err != nil {
				return false
			}
			return bytes.Equal(out.Bytes(), data)
		}
		if !errors.Is(err, ErrSizeExceeded) {
			return false
		}
		if out.Len() != int(maxBytes) {
			return false
		}
		return bytes.Equal(out.Bytes(), data[:maxBytes])
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("CopyWithStrictLimit property failed: %v", err)
	}
}

func TestCopyWithStrictLimitEdgeCases(t *testing.T) {
	t.Run("rejects negative limit", func(t *testing.T) {
		var out bytes.Buffer
		_, err := CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), -1)
		if !errors.Is(err, ErrSizeExceeded) {
			t.Fatalf("expected ErrSizeExceeded, got %v", err)
		}
	})

	t.Run("zero limit accepts empty input", func(t *testing.T) {
		var out bytes.Buffer
		written, err := CopyWithStrictLimit(&out, bytes.NewReader(nil), 0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if written != 0 || out.Len() != 0 {
			t.Fatalf("expected zero write, got written=%d len=%d", written, out.Len())
		}
	})

	t.Run("zero limit rejects non-empty input", func(t *testing.T) {
		var out bytes.Buffer
		_, err := CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), 0)
		if !errors.Is(err, ErrSizeExceeded) {
			t.Fatalf("expected ErrSizeExceeded, got %v", err)
		}
	})

	t.Run("propagates destination write errors", func(t *testing.T) {
		dst := &failingWriter{failAfter: 0}
		_, err := CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("returns short write when destination truncates", func(t *testing.T) {
		dst := &shortWriter{}
		_, err := CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("expected io.ErrShortWrite, got %v", err)
		}
	})

	t.Run("propagates reader errors", func(t *testing.T) {
		src := &failingReader{
			data:      []byte("abc"),
			failAfter: 1,
			err:       errors.New("read failed"),
		}
		var out bytes.Buffer
		_, err := CopyWithStrictLimit(&out, src, 1)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestIsSizeExceeded(t *testing.T) {
	t.Run("matches sentinel", func(t *testing.T) {
		if !IsSizeExceeded(ErrSizeExceeded) {
			t.Fatalf("expected sentinel to match")
		}
	})

	t.Run("matches wrapped sentinel", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrSizeExceeded)
		if !IsSizeExceeded(err) {
			t.Fatalf("expected wrapped sentinel to match")
		}
	})

	t.Run("does not match text-only errors", func(t *testing.T) {
		err := errors.New("size exceeds limit in downstream system")
		if IsSizeExceeded(err) {
			t.Fatalf("did not expect text-only error to match")
		}
	})
}

func TestCopyFileWithModeChecked(t *testing.T) {
	t.Run("reports source open errors", func(t *testing.T) {
		_, err := CopyFileWithModeChecked(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out"), 0o644, 1024, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open source file") {
			t.Fatalf("expected source-open error, got %v", err)
		}
	})

	t.Run("reports destination create errors", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "dir")
		if err := os.Mkdir(dst, 0o755); err != nil {
			t.Fatalf("mkdir dst dir: %v", err)
		}

		_, err := CopyFileWithModeChecked(src, dst, 0o644, 1024, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to create destination file") {
			t.Fatalf("expected destination-create error, got %v", err)
		}
	})

	t.Run("copies file with mode and reports bytes", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "out.txt")

		written, err := CopyFileWithModeChecked(src, dst, 0o640, 1024, nil, nil)
		if err != nil {
			t.Fatalf("CopyFileWithModeChecked() error = %v", err)
		}
		if written != 5 {
			t.Fatalf("written = %d, want 5", written)
		}
		out, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("read dst: %v", err)
		}
		if string(out) != "hello" {
			t.Fatalf("destination contents = %q", string(out))
		}
		info, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("stat dst: %v", err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
		}
	})

	t.Run("removes partial destination on overflow", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src.txt")
		if err := os.WriteFile(src, []byte("xx"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dst := filepath.Join(t.TempDir(), "out.txt")

		_, err := CopyFileWithModeChecked(src, dst, 0o644, 1, nil, nil)
		if !errors.Is(err, ErrSizeExceeded) {
			t.Fatalf("expected ErrSizeExceeded, got %v", err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("destination should be removed, statErr=%v", statErr)
		}
	})

	t.Run("removes partial destination on read error", func(t *testing.T) {
		srcDir := t.TempDir()
		dst := filepath.Join(t.TempDir(), "out.txt")

		_, err := CopyFileWithModeChecked(srcDir, dst, 0o644, 1024, nil, nil)
		if err == nil {
			t.Fatal("expected read error")
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("destination should be removed, statErr=%v", statErr)
		}
	})

	t.Run("runs stable check before creating destination", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src.txt")
		if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		info, err := os.Lstat(src)
		if err != nil {
			t.Fatalf("lstat src: %v", err)
		}
		dst := filepath.Join(root, "out.txt")
		checkErr := errors.New("changed")

		_, err = CopyFileWithModeChecked(src, dst, 0o644, 1024, info, func(os.FileInfo, FileInfoStatter, string) error {
			return checkErr
		})
		if !errors.Is(err, checkErr) {
			t.Fatalf("expected stable-check error, got %v", err)
		}
		if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
			t.Fatalf("destination should not be created, statErr=%v", statErr)
		}
	})
}

func TestHashSHA256FileWithLimitChecked(t *testing.T) {
	t.Run("reports open errors", func(t *testing.T) {
		_, _, err := HashSHA256FileWithLimitChecked(filepath.Join(t.TempDir(), "missing"), 1024, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to open file for hashing") {
			t.Fatalf("expected hash open error, got %v", err)
		}
	})

	t.Run("hashes file and reports bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data.bin")
		if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
			t.Fatalf("write data: %v", err)
		}

		sum, size, err := HashSHA256FileWithLimitChecked(path, 1024, nil, nil)
		if err != nil {
			t.Fatalf("HashSHA256FileWithLimitChecked() error = %v", err)
		}
		if size != 3 {
			t.Fatalf("size = %d, want 3", size)
		}
		if sum != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Fatalf("sum = %s", sum)
		}
	})

	t.Run("enforces limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data.bin")
		if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
			t.Fatalf("write data: %v", err)
		}

		_, _, err := HashSHA256FileWithLimitChecked(path, 2, nil, nil)
		if !errors.Is(err, ErrSizeExceeded) {
			t.Fatalf("expected ErrSizeExceeded, got %v", err)
		}
	})

	t.Run("wraps hash read errors", func(t *testing.T) {
		dir := t.TempDir()
		_, _, err := HashSHA256FileWithLimitChecked(dir, 1024, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "failed to hash file") {
			t.Fatalf("expected hash read error, got %v", err)
		}
	})

	t.Run("runs stable check", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "data.bin")
		if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
			t.Fatalf("write data: %v", err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("lstat data: %v", err)
		}
		checkErr := errors.New("changed")

		_, _, err = HashSHA256FileWithLimitChecked(path, 1024, info, func(os.FileInfo, FileInfoStatter, string) error {
			return checkErr
		})
		if !errors.Is(err, checkErr) {
			t.Fatalf("expected stable-check error, got %v", err)
		}
	})
}

type failingWriter struct {
	failAfter int
	writes    int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.writes >= w.failAfter {
		return 0, errors.New("write failed")
	}
	w.writes++
	return len(p), nil
}

type shortWriter struct{}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type failingReader struct {
	data      []byte
	offset    int
	failAfter int
	err       error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	if r.offset >= r.failAfter {
		return 0, r.err
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
