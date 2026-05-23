package source

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watany-dev/gokui/internal/materialize"
)

const (
	maxGitHubArchiveBytes    = 100 * 1024 * 1024
	ruleGitHubArchiveScheme  = "GITHUB_ARCHIVE_SCHEME_INVALID"
	ruleGitHubRedirectHost   = "GITHUB_ARCHIVE_REDIRECT_HOST_MISMATCH"
	ruleGitHubRedirectPort   = "GITHUB_ARCHIVE_REDIRECT_PORT_MISMATCH"
	ruleGitHubRedirectScheme = "GITHUB_ARCHIVE_REDIRECT_SCHEME_INVALID"
	ruleGitHubRedirectAuth   = "GITHUB_ARCHIVE_REDIRECT_USERINFO_DISALLOWED"
)

var (
	githubCodeloadBaseURL = "https://codeload.github.com"
	githubHTTPClient      = &http.Client{Timeout: 30 * time.Second}
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
	expectedHost := req.URL.Hostname()
	expectedScheme := req.URL.Scheme
	expectedPort := normalizePortForScheme(expectedScheme, req.URL.Port())

	client := *githubHTTPClient
	previousCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
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
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
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
	if resp.ContentLength > maxGitHubArchiveBytes {
		return fmt.Errorf("github archive exceeds max size")
	}

	out, err := os.OpenFile(archivePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create github archive file: %w", err)
	}
	defer out.Close()

	limited := io.LimitReader(resp.Body, maxGitHubArchiveBytes+1)
	written, err := io.Copy(out, limited)
	if err != nil {
		return fmt.Errorf("failed to write github archive: %w", err)
	}
	if written > maxGitHubArchiveBytes {
		return fmt.Errorf("github archive exceeds max size")
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
