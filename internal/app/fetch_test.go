package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestParseFetchArgs(t *testing.T) {
	t.Run("parses source out and format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "json"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Source == "" || got.Out != "/tmp/q" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		cases := [][]string{
			{},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "xml"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--bad"},
			{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github:org/repo//skills/other@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q"},
		}
		for _, in := range cases {
			if _, err := parseFetchArgs(in); err == nil {
				t.Fatalf("expected parse error for args=%v", in)
			}
		}
	})

	t.Run("parses equals syntax", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out=/tmp/q", "--format=json"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("parses compact format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "compact" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		got, err := parseFetchArgs([]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", "/tmp/q", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseFetchArgs() error = %v", err)
		}
		if got.Out != "/tmp/q" || got.Format != "sarif" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})
}

func TestRunFetch(t *testing.T) {
	t.Run("fetches commit-pinned github source", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "demo-skill")
		cleanupCalled := false

		outRoot := filepath.Join(t.TempDir(), "q")
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps(
			[]string{"github:org/repo//skills/demo-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", outRoot, "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, func() { cleanupCalled = true }, nil
				},
			},
		)
		if code != 0 {
			t.Fatalf("runFetch() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		var report fetchReport
		if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
			t.Fatalf("json parse failed: %v", err)
		}
		if report.Decision != "FETCHED" {
			t.Fatalf("decision = %q, want FETCHED", report.Decision)
		}
		fetchedRoot := filepath.Join(outRoot, "demo-skill")
		if _, err := os.Stat(filepath.Join(fetchedRoot, "SKILL.md")); err != nil {
			t.Fatalf("expected fetched SKILL.md: %v", err)
		}
		meta, ok, err := readSourceMetadata(fetchedRoot)
		if err != nil {
			t.Fatalf("readSourceMetadata() error = %v", err)
		}
		if !ok {
			t.Fatal("expected source metadata after fetch")
		}
		if meta.SourceKind != "github-source" || meta.SourceInput == "" {
			t.Fatalf("unexpected source metadata: %+v", meta)
		}
		if !cleanupCalled {
			t.Fatal("fetch cleanup should be called")
		}
	})

	t.Run("propagates fetch and collision errors", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps(
			[]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return "", nil, errors.New("boom")
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(fetch error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "boom") {
			t.Fatalf("stderr should include fetch error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "demo-collision")
		outRoot := filepath.Join(t.TempDir(), "q")
		if err := os.MkdirAll(filepath.Join(outRoot, "demo-collision"), 0o755); err != nil {
			t.Fatalf("mkdir collision path: %v", err)
		}
		stdout.Reset()
		stderr.Reset()
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/demo-collision@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", outRoot},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(collision) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "already contains skill") {
			t.Fatalf("stderr should include collision error, got %q", stderr.String())
		}
	})

	t.Run("propagates metadata write errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "meta-write-fail-skill")

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps(
			[]string{"github:org/repo//skills/meta-write-fail-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				WriteSourceMetadata: func(skillRoot string, meta sourceMetadata) error {
					return errors.New("metadata write failed")
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(metadata write error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "metadata write failed") {
			t.Fatalf("stderr should include metadata write failure, got %q", stderr.String())
		}
	})

	t.Run("propagates atomic copy errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "atomic-fail-skill")

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps(
			[]string{"github:org/repo//skills/atomic-fail-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				FetchSkillAtomic: func(skillRoot string, outRoot string, skillName string) (string, error) {
					return "", errors.New("atomic copy failed")
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(atomic error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "atomic copy failed") {
			t.Fatalf("stderr should include atomic error, got %q", stderr.String())
		}
	})

	t.Run("validates frontmatter and supports human output", func(t *testing.T) {
		bad := t.TempDir()
		if err := os.WriteFile(filepath.Join(bad, "SKILL.md"), []byte("# no frontmatter"), 0o644); err != nil {
			t.Fatalf("write bad skill: %v", err)
		}
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps(
			[]string{"github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return bad, nil, nil
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(frontmatter error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "must start with YAML frontmatter") {
			t.Fatalf("stderr should include frontmatter error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "human-fetch-skill")
		stdout.Reset()
		stderr.Reset()
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/human-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir()},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
			},
		)
		if code != 0 {
			t.Fatalf("runFetch(human) code = %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "gokui fetch report (pre-release)") {
			t.Fatalf("stdout should include human header, got %q", stdout.String())
		}
	})
}
