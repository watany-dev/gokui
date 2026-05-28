package source

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadGitHubArchiveErrors(t *testing.T) {
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

}
