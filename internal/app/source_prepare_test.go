package app

import (
	"errors"
	"fmt"
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

	t.Run("github source accepts explicit fetch dependency", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "github-prepare-deps-skill")
		called := false
		root, cleanup, err := preparePolicyEvaluationSourceWithDeps(
			"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"github-source",
			policyEvaluationSourceDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					called = true
					return sourceDir, nil, nil
				},
			},
		)
		if err != nil {
			t.Fatalf("preparePolicyEvaluationSourceWithDeps(github) error = %v", err)
		}
		if cleanup != nil {
			cleanup()
		}
		if !called {
			t.Fatal("explicit fetch dependency was not called")
		}
		if filepath.Base(root) != "github-prepare-deps-skill" {
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

func TestIsGitHubRefNotPinnedError(t *testing.T) {
	t.Run("matches sentinel and wrapped sentinel", func(t *testing.T) {
		if !isGitHubRefNotPinnedError(errGitHubRefNotPinned) {
			t.Fatal("expected sentinel to match")
		}
		wrapped := fmt.Errorf("wrapped: %w", errGitHubRefNotPinned)
		if !isGitHubRefNotPinnedError(wrapped) {
			t.Fatal("expected wrapped sentinel to match")
		}
	})

	t.Run("does not match text-only error", func(t *testing.T) {
		err := errors.New("github source requires a commit-pinned ref")
		if isGitHubRefNotPinnedError(err) {
			t.Fatal("did not expect text-only error to match")
		}
	})
}
