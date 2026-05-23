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
	maxGitHubArchiveBytes  = 100 * 1024 * 1024
	ruleGitHubRedirectHost = "GITHUB_ARCHIVE_REDIRECT_HOST_MISMATCH"
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
	expectedHost := req.URL.Hostname()

	client := *githubHTTPClient
	previousCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !strings.EqualFold(next.URL.Hostname(), expectedHost) {
			return fmt.Errorf("%s: github archive redirected to unexpected host: %s", ruleGitHubRedirectHost, next.URL.Hostname())
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
	var dirs []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry)
		}
	}
	if len(dirs) != 1 {
		return "", fmt.Errorf("github archive must contain a single top-level directory")
	}
	return filepath.Join(root, dirs[0].Name()), nil
}
