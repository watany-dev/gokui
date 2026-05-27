package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/watany-dev/gokui/internal/limitio"
)

func newTestGitHubFetcher(transport http.RoundTripper, opts ...GitHubFetcherOption) *GitHubFetcher {
	allOpts := []GitHubFetcherOption{
		WithBaseURL("https://mock.codeload.local"),
		WithHTTPClient(&http.Client{Transport: transport}),
	}
	allOpts = append(allOpts, opts...)
	return NewGitHubFetcher(allOpts...)
}

func TestFetchGitHubSkill(t *testing.T) {
	archive := buildTarGz(t, map[string]string{
		"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/demo/SKILL.md":  "---\nname: demo\ndescription: Use when testing github fetch.\n---\n",
		"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/demo/README.md": "fixture",
	})
	fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://mock.codeload.local/owner/repo/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234" {
			return httpResponse(http.StatusNotFound, []byte("not found")), nil
		}
		return httpResponse(http.StatusOK, archive), nil
	}))

	spec, err := ParseGitHubSource("github:owner/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234")
	if err != nil {
		t.Fatalf("ParseGitHubSource() error = %v", err)
	}

	root, cleanup, err := fetcher.Fetch(spec)
	if err != nil {
		t.Fatalf("FetchGitHubSkill() error = %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup should not be nil")
	}
	defer cleanup()

	if filepath.Base(root) != "demo" {
		t.Fatalf("root=%q, want demo dir", root)
	}
	if _, err := os.Stat(filepath.Join(root, "SKILL.md")); err != nil {
		t.Fatalf("expected SKILL.md in fetched root: %v", err)
	}
}

func TestFetchGitHubSkillErrors(t *testing.T) {
	t.Run("requires commit pinned ref", func(t *testing.T) {
		fetcher := NewGitHubFetcher()
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "main"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "commit-pinned") {
			t.Fatalf("expected commit-pinned error, got %v", err)
		}
	})

	t.Run("rejects whitespace-padded commit ref", func(t *testing.T) {
		fetcher := NewGitHubFetcher()
		spec := GitHubSpec{
			Owner: "o",
			Repo:  "r",
			Path:  "skills/x",
			Ref:   " 8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ",
		}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "commit-pinned") {
			t.Fatalf("expected commit-pinned error for whitespace-padded ref, got %v", err)
		}
	})

	t.Run("handles non-200 response", func(t *testing.T) {
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusNotFound, []byte("missing")), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("rejects missing path in archive", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/other/SKILL.md": "---\nname: other\ndescription: d\n---\n",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, archive), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "path not found") {
			t.Fatalf("expected path-not-found error, got %v", err)
		}
	})

	t.Run("rejects source path that resolves to file", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/file-skill": "not a directory",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, archive), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/file-skill", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("expected not-a-directory error, got %v", err)
		}
	})

	t.Run("rejects archive with ambiguous top-level directories", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-a/skills/demo/SKILL.md": "---\nname: demo\ndescription: d\n---\n",
			"repo-b/skills/demo/SKILL.md": "---\nname: demo\ndescription: d\n---\n",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, archive), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/demo", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected top-level directory error, got %v", err)
		}
	})

	t.Run("rejects archive with top-level file alongside repository directory", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/demo/SKILL.md": "---\nname: demo\ndescription: d\n---\n",
			"README.md": "unexpected top-level file",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, archive), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/demo", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected top-level directory error, got %v", err)
		}
	})

	t.Run("rejects invalid tar stream", func(t *testing.T) {
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, []byte("not-a-tar-gzip")), nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/demo", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := fetcher.Fetch(spec)
		if err == nil {
			t.Fatal("expected archive extraction error")
		}
	})

	t.Run("detectSingleTopLevelDirectory handles read error", func(t *testing.T) {
		_, err := detectSingleTopLevelDirectory(filepath.Join(t.TempDir(), "missing"))
		if err == nil || !strings.Contains(err.Error(), "failed to read extracted github archive") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestGitHubFetcherDefaultTimeout(t *testing.T) {
	fetcher := NewGitHubFetcher()
	if fetcher.HTTPClient == nil {
		t.Fatal("default GitHub HTTP client must be initialized")
	}
	if fetcher.HTTPClient.Timeout != 30*time.Second {
		t.Fatalf("default GitHub HTTP client timeout = %v, want %v", fetcher.HTTPClient.Timeout, 30*time.Second)
	}
}

func TestNormalizePortForScheme(t *testing.T) {
	tests := []struct {
		name     string
		scheme   string
		rawPort  string
		expected string
	}{
		{name: "explicit port unchanged", scheme: "https", rawPort: "4443", expected: "4443"},
		{name: "https default port", scheme: "https", rawPort: "", expected: "443"},
		{name: "http default port", scheme: "http", rawPort: "", expected: "80"},
		{name: "case-insensitive scheme", scheme: "HTTPS", rawPort: "", expected: "443"},
		{name: "unknown scheme no default", scheme: "ftp", rawPort: "", expected: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePortForScheme(tc.scheme, tc.rawPort); got != tc.expected {
				t.Fatalf("normalizePortForScheme(%q, %q) = %q, want %q", tc.scheme, tc.rawPort, got, tc.expected)
			}
		})
	}
}

func TestValidateGitHubArchiveResponseHeaders(t *testing.T) {
	t.Run("accepts allowed content types", func(t *testing.T) {
		allowed := []string{
			"application/x-gzip",
			"application/gzip",
			"application/octet-stream",
		}
		for _, ct := range allowed {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.Header.Set("Content-Type", ct)
			if err := validateGitHubArchiveResponseHeaders(resp); err != nil {
				t.Fatalf("expected content type %q to pass, got %v", ct, err)
			}
		}
	})

	t.Run("rejects tar content types", func(t *testing.T) {
		rejected := []string{
			"application/x-tar",
			"application/tar; charset=binary",
		}
		for _, ct := range rejected {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.Header.Set("Content-Type", ct)
			err := validateGitHubArchiveResponseHeaders(resp)
			if err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveType) {
				t.Fatalf("expected content type %q to be rejected, got %v", ct, err)
			}
		}
	})

	t.Run("rejects malformed content type", func(t *testing.T) {
		resp := httpResponse(http.StatusOK, []byte("x"))
		resp.Header.Set("Content-Type", "???")
		if err := validateGitHubArchiveResponseHeaders(resp); err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveType) {
			t.Fatalf("expected malformed content-type error, got %v", err)
		}
	})

	t.Run("accepts empty and identity content encoding", func(t *testing.T) {
		resp := httpResponse(http.StatusOK, []byte("x"))
		resp.Header.Set("Content-Type", "application/x-gzip")
		resp.Header.Del("Content-Encoding")
		if err := validateGitHubArchiveResponseHeaders(resp); err != nil {
			t.Fatalf("expected empty content-encoding to pass, got %v", err)
		}
		resp.Header.Set("Content-Encoding", "identity")
		if err := validateGitHubArchiveResponseHeaders(resp); err != nil {
			t.Fatalf("expected identity content-encoding to pass, got %v", err)
		}
	})
}

func TestValidateGzipArchiveFile(t *testing.T) {
	t.Run("valid gzip stream passes", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		path := filepath.Join(t.TempDir(), "archive.tar.gz")
		if err := os.WriteFile(path, archive, 0o644); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		if err := validateGzipArchiveFile(path); err != nil {
			t.Fatalf("expected valid gzip stream, got %v", err)
		}
	})

	t.Run("missing archive file returns reopen error", func(t *testing.T) {
		err := validateGzipArchiveFile(filepath.Join(t.TempDir(), "missing.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "failed to reopen github archive for validation") {
			t.Fatalf("expected reopen error, got %v", err)
		}
	})

	t.Run("short payload is rejected as non-gzip", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "short.tar.gz")
		if err := os.WriteFile(path, []byte{0x1f, 0x8b}, 0o644); err != nil {
			t.Fatalf("write short payload: %v", err)
		}
		err := validateGzipArchiveFile(path)
		if err == nil || !strings.Contains(err.Error(), "github archive payload must be gzip") {
			t.Fatalf("expected short payload error, got %v", err)
		}
	})

	t.Run("trailing bytes are rejected for strict single-stream validation", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		path := filepath.Join(t.TempDir(), "trailing.tar.gz")
		payload := append(append([]byte{}, archive...), []byte("tail")...)
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			t.Fatalf("write trailing payload: %v", err)
		}
		err := validateGzipArchiveFile(path)
		if err == nil || !strings.Contains(err.Error(), "single gzip stream without trailing bytes") {
			t.Fatalf("expected trailing-bytes validation error, got %v", err)
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
		dst := &sourceFailingWriter{failAfter: 0}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("returns short write when destination truncates", func(t *testing.T) {
		dst := &sourceShortWriter{}
		_, err := limitio.CopyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("expected io.ErrShortWrite, got %v", err)
		}
	})

	t.Run("propagates reader errors", func(t *testing.T) {
		src := &sourceFailingReader{
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

type sourceFailingWriter struct {
	failAfter int
	writes    int
}

func (w *sourceFailingWriter) Write(p []byte) (int, error) {
	if w.writes >= w.failAfter {
		return 0, errors.New("write failed")
	}
	w.writes++
	return len(p), nil
}

type sourceShortWriter struct{}

func (w *sourceShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type sourceFailingReader struct {
	data      []byte
	offset    int
	failAfter int
	err       error
}

func (r *sourceFailingReader) Read(p []byte) (int, error) {
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func httpResponse(status int, body []byte) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/x-gzip")
	return resp
}

func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		data := []byte(body)
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}
