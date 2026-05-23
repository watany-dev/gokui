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
	"time"
)

func TestFetchGitHubSkill(t *testing.T) {
	origBase := githubCodeloadBaseURL
	origClient := githubHTTPClient
	t.Cleanup(func() {
		githubCodeloadBaseURL = origBase
		githubHTTPClient = origClient
	})

	archive := buildTarGz(t, map[string]string{
		"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/demo/SKILL.md":  "---\nname: demo\ndescription: Use when testing github fetch.\n---\n",
		"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/demo/README.md": "fixture",
	})
	githubCodeloadBaseURL = "https://mock.codeload.local"
	githubHTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://mock.codeload.local/owner/repo/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234" {
				return httpResponse(http.StatusNotFound, []byte("not found")), nil
			}
			return httpResponse(http.StatusOK, archive), nil
		}),
	}

	spec, err := ParseGitHubSource("github:owner/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234")
	if err != nil {
		t.Fatalf("ParseGitHubSource() error = %v", err)
	}

	root, cleanup, err := FetchGitHubSkill(spec)
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
	origBase := githubCodeloadBaseURL
	origClient := githubHTTPClient
	t.Cleanup(func() {
		githubCodeloadBaseURL = origBase
		githubHTTPClient = origClient
	})

	t.Run("requires commit pinned ref", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "main"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil || !strings.Contains(err.Error(), "commit-pinned") {
			t.Fatalf("expected commit-pinned error, got %v", err)
		}
	})

	t.Run("handles non-200 response", func(t *testing.T) {
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusNotFound, []byte("missing")), nil
			}),
		}

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil || !strings.Contains(err.Error(), "unexpected status") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("rejects missing path in archive", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/other/SKILL.md": "---\nname: other\ndescription: d\n---\n",
		})
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, archive), nil
			}),
		}

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil || !strings.Contains(err.Error(), "path not found") {
			t.Fatalf("expected path-not-found error, got %v", err)
		}
	})

	t.Run("rejects source path that resolves to file", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-8f3c2d1a4b5c6d7e8f901234567890abcdef1234/skills/file-skill": "not a directory",
		})
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, archive), nil
			}),
		}

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/file-skill", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("expected not-a-directory error, got %v", err)
		}
	})

	t.Run("rejects archive with ambiguous top-level directories", func(t *testing.T) {
		archive := buildTarGz(t, map[string]string{
			"repo-a/skills/demo/SKILL.md": "---\nname: demo\ndescription: d\n---\n",
			"repo-b/skills/demo/SKILL.md": "---\nname: demo\ndescription: d\n---\n",
		})
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, archive), nil
			}),
		}

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/demo", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected top-level directory error, got %v", err)
		}
	})

	t.Run("rejects invalid tar stream", func(t *testing.T) {
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, []byte("not-a-tar-gzip")), nil
			}),
		}

		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/demo", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		_, _, err := FetchGitHubSkill(spec)
		if err == nil {
			t.Fatal("expected archive extraction error")
		}
	})

	t.Run("downloadGitHubArchive handles request and transport errors", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}

		githubCodeloadBaseURL = "://bad-url"
		err := downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "construct github archive request") {
			t.Fatalf("expected request construction error, got %v", err)
		}

		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("dial error")
			}),
		}
		err = downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "failed to download github archive") {
			t.Fatalf("expected transport error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive handles output creation error", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return httpResponse(http.StatusOK, []byte("x")), nil
			}),
		}

		outDir := filepath.Join(t.TempDir(), "archive-dir")
		if err := os.Mkdir(outDir, 0o755); err != nil {
			t.Fatalf("mkdir outDir: %v", err)
		}
		err := downloadGitHubArchive(spec, outDir)
		if err == nil || !strings.Contains(err.Error(), "create github archive file") {
			t.Fatalf("expected archive create error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects oversized content-length", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				resp := httpResponse(http.StatusOK, []byte("x"))
				resp.ContentLength = maxGitHubArchiveBytes + 1
				return resp, nil
			}),
		}

		err := downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
			t.Fatalf("expected max-size error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive rejects redirect to different host", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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
			}),
		}

		err := downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz"))
		if err == nil || !strings.Contains(err.Error(), ruleGitHubRedirectHost) {
			t.Fatalf("expected redirect-host mismatch error, got %v", err)
		}
	})

	t.Run("downloadGitHubArchive allows redirect within same host", func(t *testing.T) {
		spec := GitHubSpec{Owner: "o", Repo: "r", Path: "skills/x", Ref: "8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}
		githubCodeloadBaseURL = "https://mock.codeload.local"
		githubHTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/o/r/tar.gz/8f3c2d1a4b5c6d7e8f901234567890abcdef1234":
					resp := httpResponse(http.StatusFound, []byte("redirect"))
					resp.Header.Set("Location", "https://mock.codeload.local/redirected/archive.tar.gz")
					return resp, nil
				case "/redirected/archive.tar.gz":
					return httpResponse(http.StatusOK, []byte("ok")), nil
				default:
					return httpResponse(http.StatusNotFound, []byte("not found")), nil
				}
			}),
		}

		if err := downloadGitHubArchive(spec, filepath.Join(t.TempDir(), "archive.tar.gz")); err != nil {
			t.Fatalf("expected same-host redirect success, got %v", err)
		}
	})

	t.Run("detectSingleTopLevelDirectory handles read error", func(t *testing.T) {
		_, err := detectSingleTopLevelDirectory(filepath.Join(t.TempDir(), "missing"))
		if err == nil || !strings.Contains(err.Error(), "failed to read extracted github archive") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestGitHubHTTPClientDefaultTimeout(t *testing.T) {
	if githubHTTPClient == nil {
		t.Fatal("githubHTTPClient must be initialized")
	}
	if githubHTTPClient.Timeout != 30*time.Second {
		t.Fatalf("githubHTTPClient timeout = %v, want %v", githubHTTPClient.Timeout, 30*time.Second)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func httpResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
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
