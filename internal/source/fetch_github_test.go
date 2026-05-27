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

	t.Run("downloadGitHubArchive handles request and transport errors", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}

		fetcher := NewGitHubFetcher(WithBaseURL("://bad-url"))
		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "construct github archive request") {
			t.Fatalf("expected request construction error, got %v", err)
		}

		fetcher = newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial error")
		}))
		err = fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "failed to download github archive") {
			t.Fatalf("expected transport error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects non-gzip payload and cleans up partial file", func(t *testing.T) {
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("plain-tar-or-text"))
			resp.Header.Set("Content-Type", "application/x-gzip")
			return resp, nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		outPath := filepath.Join(t.TempDir(), "archive.tar.gz")
		err := fetcher.downloadGitHubArchive(spec, outPath)
		if err == nil || !strings.Contains(err.Error(), "payload must be gzip") {
			t.Fatalf("expected gzip payload validation error, got %v", err)
		}
		if _, statErr := os.Stat(outPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected invalid payload archive file to be removed, statErr=%v", statErr)
		}
	})

	t.Run("downloadGitHubArchive rejects truncated gzip payload and cleans up partial file", func(t *testing.T) {
		goodArchive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		if len(goodArchive) < 12 {
			t.Fatalf("expected fixture archive large enough, got %d bytes", len(goodArchive))
		}
		truncated := goodArchive[:len(goodArchive)-8]

		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, truncated)
			resp.Header.Set("Content-Type", "application/x-gzip")
			return resp, nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		outPath := filepath.Join(t.TempDir(), "archive.tar.gz")
		err := fetcher.downloadGitHubArchive(spec, outPath)
		if err == nil || !strings.Contains(err.Error(), "payload must be valid gzip stream") {
			t.Fatalf("expected truncated-gzip validation error, got %v", err)
		}
		if _, statErr := os.Stat(outPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected truncated payload archive file to be removed, statErr=%v", statErr)
		}
	})

	t.Run("downloadGitHubArchive rejects gzip payload with trailing bytes and cleans up partial file", func(t *testing.T) {
		goodArchive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		tainted := append(append([]byte{}, goodArchive...), []byte("trailing")...)

		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, tainted)
			resp.Header.Set("Content-Type", "application/x-gzip")
			return resp, nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		outPath := filepath.Join(t.TempDir(), "archive.tar.gz")
		err := fetcher.downloadGitHubArchive(spec, outPath)
		if err == nil || !strings.Contains(err.Error(), "single gzip stream without trailing bytes") {
			t.Fatalf("expected trailing-bytes gzip validation error, got %v", err)
		}
		if _, statErr := os.Stat(outPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected trailing-bytes archive file to be removed, statErr=%v", statErr)
		}
	})

	t.Run("downloadGitHubArchive rejects concatenated gzip members and cleans up partial file", func(t *testing.T) {
		first := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		second := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/y/SKILL.md": "---\nname: y\ndescription: d\n---\n",
		})
		concatenated := append(append([]byte{}, first...), second...)

		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, concatenated)
			resp.Header.Set("Content-Type", "application/x-gzip")
			return resp, nil
		}))

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		outPath := filepath.Join(t.TempDir(), "archive.tar.gz")
		err := fetcher.downloadGitHubArchive(spec, outPath)
		if err == nil || !strings.Contains(err.Error(), "single gzip stream without trailing bytes") {
			t.Fatalf("expected concatenated-gzip validation error, got %v", err)
		}
		if _, statErr := os.Stat(outPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected concatenated-gzip archive file to be removed, statErr=%v", statErr)
		}
	})

	t.Run("downloadGitHubArchive rejects non-https base URL", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := NewGitHubFetcher(
			WithBaseURL("http://mock.codeload.local"),
			WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, []byte("x")), nil
			})}),
		)

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveScheme) {
			t.Fatalf("expected non-https scheme error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive handles output creation error", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return httpResponse(http.StatusOK, []byte("x")), nil
		}))

		outDir := filepath.Join(t.TempDir(), "archive-dir")
		if err := os.Mkdir(outDir, 0o755); err != nil {
			t.Fatalf("mkdir outDir: %v", err)
		}
		err := fetcher.downloadGitHubArchive(spec, outDir)
		if err == nil || !strings.Contains(err.Error(), "create github archive file") {
			t.Fatalf("expected archive create error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects oversized content-length", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.ContentLength = defaultMaxGitHubArchiveBytes + 1
			return resp, nil
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
			t.Fatalf("expected max-size error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive removes partial file on streamed oversize", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("12345"))
			resp.ContentLength = -1
			return resp, nil
		}), WithMaxBytes(4))

		outPath := filepath.Join(t.TempDir(), "archive.tar.gz")
		err := fetcher.downloadGitHubArchive(spec, outPath)
		if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
			t.Fatalf("expected streamed max-size error, got %v", err)
		}
		if _, statErr := os.Stat(outPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected partial archive file to be removed, statErr=%v", statErr)
		}
	})

	t.Run("downloadGitHubArchive rejects missing content-type", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.Header.Del("Content-Type")
			return resp, nil
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveType) {
			t.Fatalf("expected content-type validation error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects unsupported content-type", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			return resp, nil
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveType) {
			t.Fatalf("expected unsupported content-type error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects unexpected content-encoding", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			resp := httpResponse(http.StatusOK, []byte("x"))
			resp.Header.Set("Content-Encoding", "gzip")
			return resp, nil
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubArchiveCoding) {
			t.Fatalf("expected content-encoding validation error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects redirect to different host", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Host {
			case "mock.codeload.local":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "https://evil.example/archive.tar.gz")
				return resp, nil
			case "evil.example":
				return httpResponse(http.StatusOK, []byte("evil")), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubRedirectHost) {
			t.Fatalf("expected redirect-host mismatch error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects redirect to different scheme", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "http://mock.codeload.local/redirected/archive.tar.gz")
				return resp, nil
			case "/redirected/archive.tar.gz":
				return httpResponse(http.StatusOK, []byte("ok")), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubRedirectScheme) {
			t.Fatalf("expected redirect-scheme mismatch error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive allows redirect within same host", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "https://mock.codeload.local/redirected/archive.tar.gz")
				return resp, nil
			case "/redirected/archive.tar.gz":
				return httpResponse(http.StatusOK, archive), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		if err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz")); err != nil {
			t.Fatalf("expected same-host redirect success, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects redirect to different port on same host", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "https://mock.codeload.local:4443/redirected/archive.tar.gz")
				return resp, nil
			case "/redirected/archive.tar.gz":
				return httpResponse(http.StatusOK, []byte("ok")), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubRedirectPort) {
			t.Fatalf("expected redirect-port mismatch error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects redirect with userinfo", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "https://user:pass@mock.codeload.local/redirected/archive.tar.gz")
				return resp, nil
			case "/redirected/archive.tar.gz":
				return httpResponse(http.StatusOK, []byte("ok")), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubRedirectAuth) {
			t.Fatalf("expected redirect-userinfo disallowed error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive allows explicit default-port redirect", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/x/SKILL.md": "---\nname: x\ndescription: d\n---\n",
		})
		fetcher := newTestGitHubFetcher(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
				resp := httpResponse(http.StatusFound, []byte("redirect"))
				resp.Header.Set("Location", "https://mock.codeload.local:443/redirected/archive.tar.gz")
				return resp, nil
			case "/redirected/archive.tar.gz":
				return httpResponse(http.StatusOK, archive), nil
			default:
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
		}))

		if err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz")); err != nil {
			t.Fatalf("expected same-host default-port redirect success, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive enforces redirect limit before permissive custom policy", func(t *testing.T) {
		previousCalls := 0
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		fetcher := NewGitHubFetcher(
			WithBaseURL("https://mock.codeload.local"),
			WithMaxRedirects(3),
			WithHTTPClient(&http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					previousCalls++
					return nil
				},
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					resp := httpResponse(http.StatusFound, []byte("redirect"))
					resp.Header.Set("Location", "https://mock.codeload.local/loop")
					return resp, nil
				}),
			}),
		)

		err := fetcher.downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "stopped after 3 redirects") {
			t.Fatalf("expected redirect-limit error, got %v", err)
		}
		if previousCalls == 0 {
			t.Fatal("expected previous CheckRedirect to be invoked before limit is hit")
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
		written, err := copyWithStrictLimit(&out, bytes.NewReader(data), maxBytes)
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
		_, err := copyWithStrictLimit(&out, bytes.NewReader([]byte("x")), -1)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected negative-limit error, got %v", err)
		}
	})

	t.Run("zero limit accepts empty input", func(t *testing.T) {
		var out bytes.Buffer
		written, err := copyWithStrictLimit(&out, bytes.NewReader(nil), 0)
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if written != 0 || out.Len() != 0 {
			t.Fatalf("expected zero write, got written=%d len=%d", written, out.Len())
		}
	})

	t.Run("zero limit rejects non-empty input", func(t *testing.T) {
		var out bytes.Buffer
		_, err := copyWithStrictLimit(&out, bytes.NewReader([]byte("x")), 0)
		if err == nil || !strings.Contains(err.Error(), "size exceeds limit") {
			t.Fatalf("expected size-limit error, got %v", err)
		}
	})

	t.Run("propagates destination write errors", func(t *testing.T) {
		dst := &sourceFailingWriter{failAfter: 0}
		_, err := copyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("returns short write when destination truncates", func(t *testing.T) {
		dst := &sourceShortWriter{}
		_, err := copyWithStrictLimit(dst, bytes.NewReader([]byte("abc")), 10)
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
		_, err := copyWithStrictLimit(&out, src, 1)
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
