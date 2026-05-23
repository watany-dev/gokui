package source

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	githubRepoPartPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	commitRefPattern      = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// GitHubSpec is a parsed github source in the form:
// github:owner/repo//path/to/skill@ref
type GitHubSpec struct {
	Owner string
	Repo  string
	Path  string
	Ref   string
}

// ParseGitHubSource parses and validates github source syntax.
func ParseGitHubSource(input string) (GitHubSpec, error) {
	const prefix = "github:"
	if !strings.HasPrefix(input, prefix) {
		return GitHubSpec{}, fmt.Errorf("github source must start with %q", prefix)
	}

	rest := strings.TrimPrefix(input, prefix)
	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return GitHubSpec{}, fmt.Errorf("github source must include @ref: github:owner/repo//path@ref")
	}
	location := rest[:at]
	ref := rest[at+1:]
	if strings.TrimSpace(ref) != ref {
		return GitHubSpec{}, fmt.Errorf("github source ref must not contain surrounding spaces")
	}

	parts := strings.SplitN(location, "//", 2)
	if len(parts) != 2 {
		return GitHubSpec{}, fmt.Errorf("github source must include //path segment: github:owner/repo//path@ref")
	}

	repoParts := strings.Split(parts[0], "/")
	if len(repoParts) != 2 {
		return GitHubSpec{}, fmt.Errorf("github source must include owner/repo")
	}
	if strings.TrimSpace(repoParts[0]) != repoParts[0] || strings.TrimSpace(repoParts[1]) != repoParts[1] {
		return GitHubSpec{}, fmt.Errorf("github source owner/repo must not contain surrounding spaces")
	}
	owner := strings.TrimSpace(repoParts[0])
	repo := strings.TrimSpace(repoParts[1])
	if owner == "" || repo == "" {
		return GitHubSpec{}, fmt.Errorf("github source owner/repo must be non-empty")
	}
	if !githubRepoPartPattern.MatchString(owner) || !githubRepoPartPattern.MatchString(repo) {
		return GitHubSpec{}, fmt.Errorf("github source owner/repo contains invalid characters")
	}

	skillPath, err := normalizeGitHubPath(parts[1])
	if err != nil {
		return GitHubSpec{}, err
	}

	return GitHubSpec{
		Owner: owner,
		Repo:  repo,
		Path:  skillPath,
		Ref:   ref,
	}, nil
}

func normalizeGitHubPath(p string) (string, error) {
	raw := strings.TrimSpace(p)
	if raw == "" {
		return "", fmt.Errorf("github source path must be non-empty")
	}
	if strings.Contains(raw, `\`) {
		return "", fmt.Errorf("github source path must use forward slashes")
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("github source path must be relative")
	}

	clean := path.Clean(raw)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("github source path must be non-empty")
	}
	if strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("github source path must not escape repository root")
	}
	return clean, nil
}

// IsCommitPinnedRef returns true when ref looks like a commit SHA.
func IsCommitPinnedRef(ref string) bool {
	return commitRefPattern.MatchString(strings.TrimSpace(ref))
}
