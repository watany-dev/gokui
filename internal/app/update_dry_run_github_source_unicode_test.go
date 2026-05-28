package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUpdateDryRunGitHubSourceUnicodeLockErrors(t *testing.T) {
	t.Run("github source with path bidi-control in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-bidi-control"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-bidi-control skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-bidi-control",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-bidi-control", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-bidi-control) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with path zero-width char in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-zero-width"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-zero-width skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-zero-width",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-zero-width", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-zero-width) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with path whitespace char in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with unicode-whitespace ref in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-ref-unicode-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir github-ref-unicode-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-ref-unicode-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-ref-unicode-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source ref-unicode-whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with zero-width ref in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-ref-zero-width"), 0o755); err != nil {
			t.Fatalf("mkdir github-ref-zero-width skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-ref-zero-width",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-ref-zero-width", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source ref-zero-width) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with bidi-control ref in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-ref-bidi-control"), 0o755); err != nil {
			t.Fatalf("mkdir github-ref-bidi-control skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-ref-bidi-control",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-ref-bidi-control", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source ref-bidi-control) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with unicode-tag ref in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-ref-unicode-tag"), 0o755); err != nil {
			t.Fatalf("mkdir github-ref-unicode-tag skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-ref-unicode-tag",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\U000E00011234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-ref-unicode-tag", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source ref-unicode-tag) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with variation-selector ref in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-ref-variation-selector"), 0o755); err != nil {
			t.Fatalf("mkdir github-ref-variation-selector skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-ref-variation-selector",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8f3c2d1a4b5c6d7e8f90\ufe0f1234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-ref-variation-selector", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source ref-variation-selector) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with unicode-whitespace owner in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-owner-unicode-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir github-owner-unicode-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-owner-unicode-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:or\u00a0g/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-owner-unicode-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source owner-unicode-whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with zero-width repo in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-zero-width"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-zero-width skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-zero-width",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/re\u200bpo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-zero-width", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source repo-zero-width) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with unicode tag in owner in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-owner-unicode-tag"), 0o755); err != nil {
			t.Fatalf("mkdir github-owner-unicode-tag skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-owner-unicode-tag",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:or\U000E0001g/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-owner-unicode-tag", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source owner-unicode-tag) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with variation-selector repo in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-variation-selector"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-variation-selector skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-variation-selector",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/re\ufe0fpo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-variation-selector", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source repo-variation-selector) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})
}
