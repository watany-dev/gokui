package limitio

import (
	"bytes"
	"errors"
	"io"
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
