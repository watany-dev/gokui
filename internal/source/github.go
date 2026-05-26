package source

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	githubOwnerPartPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	githubRepoPartPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	commitRefPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	commitRefHexPattern    = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	comLptSuffixPattern    = regexp.MustCompile(`^(com|lpt)[1-9]$`)
)

const (
	maxGitHubSourceInputChars = 4096
	maxGitHubOwnerChars       = 39
	maxGitHubRepoChars        = 100
	maxGitHubPathChars        = 1024
	maxGitHubRefChars         = 255
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
	if containsASCIIControlCharacters(input) {
		return GitHubSpec{}, fmt.Errorf("github source must not contain ASCII control characters")
	}
	if len(input) > maxGitHubSourceInputChars {
		return GitHubSpec{}, fmt.Errorf("github source exceeds max length: %d", maxGitHubSourceInputChars)
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
	if commitRefHexPattern.MatchString(ref) && !commitRefPattern.MatchString(ref) {
		return GitHubSpec{}, fmt.Errorf("github source commit ref must be canonical lowercase 40-hex")
	}
	if len(ref) > maxGitHubRefChars {
		return GitHubSpec{}, fmt.Errorf("github source ref exceeds max length: %d", maxGitHubRefChars)
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
	if len(owner) > maxGitHubOwnerChars {
		return GitHubSpec{}, fmt.Errorf("github source owner exceeds max length: %d", maxGitHubOwnerChars)
	}
	if len(repo) > maxGitHubRepoChars {
		return GitHubSpec{}, fmt.Errorf("github source repo exceeds max length: %d", maxGitHubRepoChars)
	}
	if !githubOwnerPartPattern.MatchString(owner) || !githubRepoPartPattern.MatchString(repo) {
		return GitHubSpec{}, fmt.Errorf("github source owner/repo contains invalid characters")
	}
	if owner == "." || owner == ".." || repo == "." || repo == ".." {
		return GitHubSpec{}, fmt.Errorf("github source owner/repo must not use dot segments")
	}
	if strings.HasPrefix(owner, "-") || strings.HasSuffix(owner, "-") || strings.Contains(owner, "--") {
		return GitHubSpec{}, fmt.Errorf("github source owner must be canonical github login format")
	}
	if owner != strings.ToLower(owner) {
		return GitHubSpec{}, fmt.Errorf("github source owner must be canonical lowercase github login format")
	}
	if repo != strings.ToLower(repo) {
		return GitHubSpec{}, fmt.Errorf("github source repo must be canonical lowercase")
	}
	if strings.HasPrefix(repo, ".") || strings.HasSuffix(repo, ".") {
		return GitHubSpec{}, fmt.Errorf("github source repo must not start or end with dot")
	}
	if strings.HasSuffix(strings.ToLower(repo), ".git") {
		return GitHubSpec{}, fmt.Errorf("github source repo must not include .git suffix")
	}
	if strings.Contains(repo, "..") {
		return GitHubSpec{}, fmt.Errorf("github source repo must not contain consecutive dots")
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
	if raw != p {
		return "", fmt.Errorf("github source path must not contain surrounding spaces")
	}
	if raw == "" {
		return "", fmt.Errorf("github source path must be non-empty")
	}
	if strings.Contains(raw, `\`) {
		return "", fmt.Errorf("github source path must use forward slashes")
	}
	if strings.Contains(raw, "@") {
		return "", fmt.Errorf("github source path must not contain @")
	}
	if strings.Contains(raw, ":") {
		return "", fmt.Errorf("github source path must not contain colon character")
	}
	if containsZeroWidthCharacter(raw) {
		return "", fmt.Errorf("github source path must not contain zero-width characters")
	}
	if containsUnicodeBidiControl(raw) {
		return "", fmt.Errorf("github source path must not contain Unicode bidi control characters")
	}
	if strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("github source path must be relative")
	}

	clean := path.Clean(raw)
	if clean == "." || clean == "" {
		return "", fmt.Errorf("github source path must be non-empty")
	}
	if clean != raw {
		return "", fmt.Errorf("github source path must be canonical without empty, dot, or trailing-slash segments")
	}
	if strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("github source path must not escape repository root")
	}
	for _, segment := range strings.Split(clean, "/") {
		if strings.TrimSpace(segment) != segment {
			return "", fmt.Errorf("github source path segments must not contain surrounding spaces")
		}
		if strings.HasSuffix(segment, ".") {
			return "", fmt.Errorf("github source path segments must not end with dot")
		}
		if isWindowsReservedPathSegment(segment) {
			return "", fmt.Errorf("github source path must not contain Windows reserved device-name segments")
		}
	}
	if len(clean) > maxGitHubPathChars {
		return "", fmt.Errorf("github source path exceeds max length: %d", maxGitHubPathChars)
	}
	return clean, nil
}

func isWindowsReservedPathSegment(segment string) bool {
	trimmed := strings.TrimRight(strings.ToLower(segment), " .")
	if trimmed == "" {
		return false
	}
	base := trimmed
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = normalizeWindowsSuperscriptDigits(base)
	switch base {
	case "con", "prn", "aux", "nul", "conin$", "conout$":
		return true
	}
	return comLptSuffixPattern.MatchString(base)
}

func normalizeWindowsSuperscriptDigits(s string) string {
	return strings.NewReplacer("¹", "1", "²", "2", "³", "3").Replace(s)
}

// IsCommitPinnedRef returns true when ref looks like a commit SHA.
func IsCommitPinnedRef(ref string) bool {
	return commitRefPattern.MatchString(ref)
}

func containsASCIIControlCharacters(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func containsUnicodeBidiControl(s string) bool {
	for _, r := range s {
		switch r {
		case '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069':
			return true
		}
	}
	return false
}

func containsZeroWidthCharacter(s string) bool {
	for _, r := range s {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			return true
		}
	}
	return false
}
