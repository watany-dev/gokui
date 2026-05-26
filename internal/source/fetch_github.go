package source

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watany-dev/gokui/internal/limitio"
	"github.com/watany-dev/gokui/internal/materialize"
)

const (
	ruleGitHubArchiveScheme  = "GITHUB_ARCHIVE_SCHEME_INVALID"
	ruleGitHubRedirectHost   = "GITHUB_ARCHIVE_REDIRECT_HOST_MISMATCH"
	ruleGitHubRedirectPort   = "GITHUB_ARCHIVE_REDIRECT_PORT_MISMATCH"
	ruleGitHubRedirectScheme = "GITHUB_ARCHIVE_REDIRECT_SCHEME_INVALID"
	ruleGitHubRedirectAuth   = "GITHUB_ARCHIVE_REDIRECT_USERINFO_DISALLOWED"
	ruleGitHubArchiveType    = "GITHUB_ARCHIVE_CONTENT_TYPE_INVALID"
	ruleGitHubArchiveCoding  = "GITHUB_ARCHIVE_CONTENT_ENCODING_INVALID"
)

var (
	githubCodeloadBaseURL       = "https://codeload.github.com"
	githubHTTPClient            = &http.Client{Timeout: 30 * time.Second}
	maxGitHubArchiveBytes int64 = 100 * 1024 * 1024
	maxGitHubRedirects          = 10
)

// FetchGitHubSkill downloads and materializes a commit-pinned GitHub skill source
// into a temporary local directory and returns that directory plus a cleanup func.
func FetchGitHubSkill(spec GitHubSpec) (string, func(), error) {
	if !IsCommitPinnedRef(spec.Ref) {
		return "", nil, fmt.Errorf("github source fetch requires commit-pinned ref")
	}

	tempRoot, err := os.MkdirTemp("", "gokui-github-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create github fetch temp directory: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempRoot)
	}

	archivePath := filepath.Join(tempRoot, "repo.tar.gz")
	if err := downloadGitHubArchive(spec, archivePath); err != nil {
		cleanup()
		return "", nil, err
	}

	extractDir := filepath.Join(tempRoot, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to prepare github extract directory: %w", err)
	}

	limits := materialize.Limits{
		MaxFiles:      5000,
		MaxTotalBytes: 100 * 1024 * 1024,
		MaxFileBytes:  20 * 1024 * 1024,
	}
	if err := materialize.ExtractArchive(archivePath, "tar", extractDir, limits); err != nil {
		cleanup()
		return "", nil, err
	}

	repoRoot, err := detectSingleTopLevelDirectory(extractDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	skillRoot := filepath.Join(repoRoot, filepath.FromSlash(spec.Path))
	info, err := os.Stat(skillRoot)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("github source path not found in repository archive: %s", spec.Path)
	}
	if !info.IsDir() {
		cleanup()
		return "", nil, fmt.Errorf("github source path is not a directory: %s", spec.Path)
	}

	return skillRoot, cleanup, nil
}

func downloadGitHubArchive(spec GitHubSpec, archivePath string) error {
	url := fmt.Sprintf("%s/%s/%s/tar.gz/%s",
		strings.TrimRight(githubCodeloadBaseURL, "/"),
		spec.Owner,
		spec.Repo,
		spec.Ref,
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to construct github archive request: %w", err)
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("%s: github archive URL must use https: %s", ruleGitHubArchiveScheme, req.URL.String())
	}
	req.Header.Set("Accept-Encoding", "identity")
	expectedHost := req.URL.Hostname()
	expectedScheme := req.URL.Scheme
	expectedPort := normalizePortForScheme(expectedScheme, req.URL.Port())

	client := *githubHTTPClient
	previousCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxGitHubRedirects {
			return fmt.Errorf("stopped after %d redirects", maxGitHubRedirects)
		}
		if !strings.EqualFold(next.URL.Scheme, expectedScheme) {
			return fmt.Errorf("%s: github archive redirected to unexpected scheme: %s", ruleGitHubRedirectScheme, next.URL.Scheme)
		}
		if next.URL.User != nil {
			return fmt.Errorf("%s: github archive redirected with disallowed userinfo", ruleGitHubRedirectAuth)
		}
		if !strings.EqualFold(next.URL.Hostname(), expectedHost) {
			return fmt.Errorf("%s: github archive redirected to unexpected host: %s", ruleGitHubRedirectHost, next.URL.Hostname())
		}
		nextPort := normalizePortForScheme(next.URL.Scheme, next.URL.Port())
		if expectedPort != nextPort {
			return fmt.Errorf("%s: github archive redirected to unexpected port: %s", ruleGitHubRedirectPort, next.URL.Port())
		}
		if previousCheckRedirect != nil {
			return previousCheckRedirect(next, via)
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download github archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download github archive: unexpected status %d", resp.StatusCode)
	}
	if err := validateGitHubArchiveResponseHeaders(resp); err != nil {
		return err
	}
	if resp.ContentLength > maxGitHubArchiveBytes {
		return fmt.Errorf("github archive exceeds max size")
	}

	out, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create github archive file: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	_, err = copyWithStrictLimit(out, resp.Body, maxGitHubArchiveBytes)
	if err != nil {
		_ = os.Remove(archivePath)
		if limitio.IsSizeExceeded(err) {
			return fmt.Errorf("github archive exceeds max size")
		}
		return fmt.Errorf("failed to write github archive: %w", err)
	}
	if err := validateGzipArchiveFile(archivePath); err != nil {
		_ = os.Remove(archivePath)
		return err
	}

	return nil
}

func detectSingleTopLevelDirectory(root string) (string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("failed to read extracted github archive: %w", err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", fmt.Errorf("github archive must contain a single top-level directory")
	}
	return filepath.Join(root, entries[0].Name()), nil
}

func normalizePortForScheme(scheme string, rawPort string) string {
	if rawPort != "" {
		return rawPort
	}
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func validateGitHubArchiveResponseHeaders(resp *http.Response) error {
	contentEncoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	if contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity") {
		return fmt.Errorf("%s: github archive response uses unexpected content encoding: %s", ruleGitHubArchiveCoding, contentEncoding)
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return fmt.Errorf("%s: github archive response missing content type", ruleGitHubArchiveType)
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("%s: github archive response has invalid content type: %s", ruleGitHubArchiveType, contentType)
	}
	switch strings.ToLower(mediaType) {
	case "application/x-gzip", "application/gzip", "application/octet-stream":
		return nil
	default:
		return fmt.Errorf("%s: github archive response has unsupported content type: %s", ruleGitHubArchiveType, mediaType)
	}
}

func copyWithStrictLimit(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	return limitio.CopyWithStrictLimit(dst, src, maxBytes)
}

func validateGzipArchiveFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to reopen github archive for validation: %w", err)
	}
	defer f.Close()

	buffered := bufio.NewReader(f)
	header, err := buffered.Peek(3)
	if err != nil {
		return fmt.Errorf("github archive payload must be gzip: %w", err)
	}
	if header[0] != 0x1f || header[1] != 0x8b || header[2] != 0x08 {
		return fmt.Errorf("github archive payload must be gzip")
	}
	gz, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("github archive payload must be gzip: %w", err)
	}
	gz.Multistream(false)
	if _, err := io.Copy(io.Discard, gz); err != nil {
		_ = gz.Close()
		return fmt.Errorf("github archive payload must be valid gzip stream: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("github archive payload must be valid gzip stream: %w", err)
	}
	if _, err := buffered.ReadByte(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("failed to validate github archive trailing bytes: %w", err)
		}
		return fmt.Errorf("github archive payload must be a single gzip stream without trailing bytes")
	}
	return nil
}
