package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestPreparePolicyEvaluationSource(t *testing.T) {
	t.Run("local source delegates to inspect preparation", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "local-prepare-skill")
		root, cleanup, err := preparePolicyEvaluationSource(sourceDir, "local-dir")
		if err != nil {
			t.Fatalf("preparePolicyEvaluationSource(local) error = %v", err)
		}
		if cleanup != nil {
			cleanup()
		}
		if filepath.Base(root) != "local-prepare-skill" {
			t.Fatalf("unexpected root: %q", root)
		}
	})

	t.Run("github source requires pinned ref", func(t *testing.T) {
		_, _, err := preparePolicyEvaluationSource("github:org/repo//skills/demo@main", "github-source")
		if err == nil || !strings.Contains(err.Error(), "commit-pinned ref") {
			t.Fatalf("expected commit-pinned error, got %v", err)
		}
	})

	t.Run("github source rejects invalid syntax", func(t *testing.T) {
		_, _, err := preparePolicyEvaluationSource("github:org/repo/skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source")
		if err == nil || !strings.Contains(err.Error(), "invalid github source") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("github source uses fetcher and validates result", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "github-prepare-skill")
		origFetch := fetchGitHubSkill
		t.Cleanup(func() { fetchGitHubSkill = origFetch })
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return sourceDir, nil, nil
		}

		root, cleanup, err := preparePolicyEvaluationSource("github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source")
		if err != nil {
			t.Fatalf("preparePolicyEvaluationSource(github) error = %v", err)
		}
		if cleanup != nil {
			cleanup()
		}
		if filepath.Base(root) != "github-prepare-skill" {
			t.Fatalf("unexpected root: %q", root)
		}
	})

	t.Run("github fetch error and cleanup on validation failure", func(t *testing.T) {
		origFetch := fetchGitHubSkill
		t.Cleanup(func() { fetchGitHubSkill = origFetch })

		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return "", nil, errors.New("fetch failed")
		}
		_, _, err := preparePolicyEvaluationSource("github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source")
		if err == nil || !strings.Contains(err.Error(), "fetch failed") {
			t.Fatalf("expected fetch error, got %v", err)
		}

		cleaned := false
		badSource := t.TempDir()
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return badSource, func() { cleaned = true }, nil
		}
		_, _, err = preparePolicyEvaluationSource("github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source")
		if err == nil {
			t.Fatal("expected validation error for missing SKILL.md")
		}
		if !cleaned {
			t.Fatal("cleanup should run when validation fails")
		}
	})
}
