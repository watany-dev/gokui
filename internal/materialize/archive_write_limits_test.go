package materialize

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"

	"github.com/watany-dev/gokui/internal/limitio"
)

func TestWriteZipAndTarFileLimits(t *testing.T) {
	t.Run("writeZipFile read failure from corrupted payload", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "corrupt.zip")
		createZip(t, zipPath, map[string]string{
			"SKILL.md": strings.Repeat("abcd", 100),
		})

		reader, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open reader: %v", err)
		}
		offset, err := reader.File[0].DataOffset()
		reader.Close()
		if err != nil {
			t.Fatalf("data offset: %v", err)
		}

		file, err := os.OpenFile(zipPath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open zip for corruption: %v", err)
		}
		if _, err := file.WriteAt([]byte{0x00, 0x00, 0x00, 0x00}, offset+4); err != nil {
			file.Close()
			t.Fatalf("corrupt payload: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close corrupted zip: %v", err)
		}

		reader, err = zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("reopen reader: %v", err)
		}
		defer reader.Close()

		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeZipFile(reader.File[0], out, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "failed to extract file") {
			t.Fatalf("expected extract error, got %v", err)
		}
	})

	t.Run("writeZipFile exceeds max during extraction", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "sample.zip")
		createZip(t, zipPath, map[string]string{
			"SKILL.md": "12345",
		})

		reader, err := zip.OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open reader: %v", err)
		}
		defer reader.Close()

		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeZipFile(reader.File[0], out, 2)
		if err == nil || !strings.Contains(err.Error(), "max file bytes during extraction") {
			t.Fatalf("expected zip max-bytes error, got %v", err)
		}
		info, statErr := os.Stat(out)
		if statErr == nil {
			t.Fatalf("oversized output file should be removed, got size=%d path=%s", info.Size(), out)
		}
		if !os.IsNotExist(statErr) {
			t.Fatalf("expected not-exist after oversized extraction error, statErr=%v", statErr)
		}
	})

	t.Run("writeTarFile exceeds max during extraction", func(t *testing.T) {
		header := &tar.Header{Name: "SKILL.md"}
		out := filepath.Join(t.TempDir(), "SKILL.md")
		reader := tar.NewReader(singleFileTarReader(t, "SKILL.md", "12345"))
		if _, err := reader.Next(); err != nil {
			t.Fatalf("read tar header: %v", err)
		}

		_, err := writeTarFile(header, reader, out, 2)
		if err == nil || !strings.Contains(err.Error(), "max file bytes during extraction") {
			t.Fatalf("expected tar max-bytes error, got %v", err)
		}
		info, statErr := os.Stat(out)
		if statErr == nil {
			t.Fatalf("oversized output file should be removed, got size=%d path=%s", info.Size(), out)
		}
		if !os.IsNotExist(statErr) {
			t.Fatalf("expected not-exist after oversized extraction error, statErr=%v", statErr)
		}
	})

	t.Run("writeTarFile output create failure", func(t *testing.T) {
		header := &tar.Header{Name: "SKILL.md"}
		dir := filepath.Join(t.TempDir(), "existing-dir")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		reader := tar.NewReader(singleFileTarReader(t, "SKILL.md", "x"))
		if _, err := reader.Next(); err != nil {
			t.Fatalf("read tar header: %v", err)
		}

		_, err := writeTarFile(header, reader, dir, 10)
		if err == nil || !strings.Contains(err.Error(), "failed to create output file") {
			t.Fatalf("expected output-create error, got %v", err)
		}
	})

	t.Run("writeTarFile read failure", func(t *testing.T) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		header := &tar.Header{
			Name:     "SKILL.md",
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     10,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte("0123456789")); err != nil {
			t.Fatalf("write body: %v", err)
		}
		if err := tw.Close(); err != nil {
			t.Fatalf("close writer: %v", err)
		}

		raw := buf.Bytes()
		truncated := raw[:512+5]
		reader := tar.NewReader(bytes.NewReader(truncated))
		gotHeader, err := reader.Next()
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		out := filepath.Join(t.TempDir(), "SKILL.md")
		_, err = writeTarFile(gotHeader, reader, out, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "failed to extract file") {
			t.Fatalf("expected tar read error, got %v", err)
		}
	})
}

func TestCopyWithStrictLimitProperty(t *testing.T) {
	prop := func(data []byte, limit uint16) bool {
		maxBytes := int64(limit)
		var out bytes.Buffer
		written, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader(data), maxBytes)
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
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			return false
		}
		if out.Len() != int(maxBytes) {
			return false
		}
		return bytes.Equal(out.Bytes(), data[:maxBytes])
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("copyWithStrictLimit property failed: %v", err)
	}
}

func TestCopyWithStrictLimitEdgeCases(t *testing.T) {
	t.Run("rejects negative limit", func(t *testing.T) {
		var out bytes.Buffer
		_, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), -1)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected negative-limit error, got %v", err)
		}
	})

	t.Run("zero limit accepts empty input", func(t *testing.T) {
		var out bytes.Buffer
		written, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader(nil), 0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if written != 0 || out.Len() != 0 {
			t.Fatalf("expected zero write, got written=%d len=%d", written, out.Len())
		}
	})

	t.Run("zero limit rejects non-empty input", func(t *testing.T) {
		var out bytes.Buffer
		_, err := limitio.CopyWithStrictLimit(&out, bytes.NewReader([]byte("x")), 0)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})

	t.Run("propagates destination write errors", func(t *testing.T) {
		dst := &failingWriter{failAfter: 0}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("returns short write when destination truncates", func(t *testing.T) {
		dst := &shortWriter{}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
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
		_, err := limitio.CopyWithStrictLimit(&out, src, 1)
		if err == nil || !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("expected read error, got %v", err)
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
