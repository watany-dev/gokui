package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestRunInstallUpdateLockCommands(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}
	t.Run("install succeeds for clean skill to custom target", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		targetRoot := filepath.Join(t.TempDir(), "skills")
		source := filepath.FromSlash("../../fixtures/clean-skill")
		code := Run([]string{"install", source, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}

		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "decision: PASS") {
			t.Fatalf("stdout should include pass decision, got %q", stdout.String())
		}

		installed := filepath.Join(targetRoot, "clean-skill")
		if _, err := os.Stat(filepath.Join(installed, "SKILL.md")); err != nil {
			t.Fatalf("expected SKILL.md in install, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(installed, ".gokui-report.json")); err != nil {
			t.Fatalf("expected report in install, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(installed, "gokui.lock")); err != nil {
			t.Fatalf("expected lockfile in install, got %v", err)
		}
	})

	t.Run("install rejects risky skill under strict profile", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		targetRoot := filepath.Join(t.TempDir(), "skills")
		source := filepath.FromSlash("../../fixtures/fake-prereq-skill")
		code := Run([]string{"install", source, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 2 {
			t.Fatalf("Run() code = %d, want 2", code)
		}

		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "decision: REJECTED") {
			t.Fatalf("stdout should include rejected decision, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "not installed") {
			t.Fatalf("stdout should include not-installed message, got %q", stdout.String())
		}
		if _, err := os.Stat(filepath.Join(targetRoot, "fake-prereq-skill")); !os.IsNotExist(err) {
			t.Fatalf("skill should not be installed, stat err=%v", err)
		}
	})

	t.Run("install validates required args and options", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"install", "--target", "codex"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "install source is required") {
			t.Fatalf("stderr should include source required error, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = Run([]string{"install", "../../fixtures/clean-skill"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "install target is required") {
			t.Fatalf("stderr should include target required error, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = Run([]string{"install", "../../fixtures/clean-skill", "--target", "codex", "--bad"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "unknown install option: --bad") {
			t.Fatalf("stderr should include unknown option error, got %q", stderr.String())
		}
	})

	t.Run("install rejects unsupported profile and target", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"install", "../../fixtures/clean-skill", "--target", "codex", "--profile", "enterprise"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "unsupported profile: enterprise") {
			t.Fatalf("stderr should include unsupported profile error, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = Run([]string{"install", "../../fixtures/clean-skill", "--target", "unsupported-target", "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "unsupported install target") {
			t.Fatalf("stderr should include unsupported target error, got %q", stderr.String())
		}
	})

	t.Run("install resolves codex target from CODEX_HOME", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		codexHome := t.TempDir()
		t.Setenv("CODEX_HOME", codexHome)

		source := filepath.FromSlash("../../fixtures/clean-skill")
		code := Run([]string{"install", source, "--target", "codex", "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		installed := filepath.Join(codexHome, "skills", "clean-skill")
		if _, err := os.Stat(installed); err != nil {
			t.Fatalf("expected installed skill in codex target, got %v", err)
		}
	})

	t.Run("install rejects github source without commit pin", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"install", "github:org/repo//skill@main", "--target", "codex", "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "requires a commit-pinned ref") {
			t.Fatalf("stderr should include commit pin requirement, got %q", stderr.String())
		}
	})

	t.Run("install github source with commit pin remains pre-release stub", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		origFetch := fetchGitHubSkill
		t.Cleanup(func() { fetchGitHubSkill = origFetch })
		fakeSource := createSkillSourceForInstallTest(t, "clean-skill")
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return fakeSource, nil, nil
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		code := Run([]string{"install", "github:org/repo//skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "decision: PASS") {
			t.Fatalf("stdout should include decision, got %q", stdout.String())
		}
	})

	t.Run("install allows idempotent reinstall with matching provenance", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		targetRoot := filepath.Join(t.TempDir(), "skills")
		source := filepath.FromSlash("../../fixtures/clean-skill")
		first := Run([]string{"install", source, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if first != 0 {
			t.Fatalf("first install code = %d, want 0", first)
		}

		stdout.Reset()
		stderr.Reset()
		second := Run([]string{"install", source, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if second != 0 {
			t.Fatalf("second install code = %d, want 0", second)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "matching provenance") {
			t.Fatalf("stdout should include matching provenance note, got %q", stdout.String())
		}
	})

	t.Run("install rejects same-name skill from different provenance", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		targetRoot := filepath.Join(t.TempDir(), "skills")
		sourceA := createSkillSourceForInstallTest(t, "same-name-skill")
		sourceB := createSkillSourceForInstallTest(t, "same-name-skill")
		if err := os.WriteFile(filepath.Join(sourceB, "README.md"), []byte("different"), 0o644); err != nil {
			t.Fatalf("write differing sourceB: %v", err)
		}

		first := Run([]string{"install", sourceA, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if first != 0 {
			t.Fatalf("first install code = %d, want 0", first)
		}

		stdout.Reset()
		stderr.Reset()
		second := Run([]string{"install", sourceB, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if second != 1 {
			t.Fatalf("second install code = %d, want 1", second)
		}
		if !strings.Contains(stderr.String(), "different provenance") {
			t.Fatalf("stderr should include provenance mismatch, got %q", stderr.String())
		}
	})

	t.Run("update command requires dry-run", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"update"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "update currently requires --dry-run") {
			t.Fatalf("stderr should include dry-run requirement, got %q", gotErr)
		}
	})

	t.Run("lock verify succeeds on installed skill", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		targetRoot := filepath.Join(t.TempDir(), "skills")
		source := filepath.FromSlash("../../fixtures/clean-skill")
		installCode := Run([]string{"install", source, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr, cfg)
		if installCode != 0 {
			t.Fatalf("install code = %d, want 0", installCode)
		}
		stdout.Reset()
		stderr.Reset()

		skillPath := filepath.Join(targetRoot, "clean-skill")
		code := Run([]string{"lock", "verify", skillPath}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "status: VERIFIED") {
			t.Fatalf("stdout should include verified status, got %q", stdout.String())
		}
	})

	t.Run("lock subcommand is required", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"lock"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "unknown command: lock") {
			t.Fatalf("stderr should include unknown lock subcommand, got %q", gotErr)
		}
		if !strings.Contains(gotErr, "gokui lock verify") {
			t.Fatalf("stderr should include lock usage, got %q", gotErr)
		}
	})
}
