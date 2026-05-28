package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUpdateDryRunGitHubSourceLockErrors(t *testing.T) {
	t.Run("invalid github source in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-invalid"), 0o755); err != nil {
			t.Fatalf("mkdir github invalid skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-invalid",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo/path@main",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-invalid", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(invalid github) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("invalid github owner format in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-owner-invalid"), 0o755); err != nil {
			t.Fatalf("mkdir github-owner-invalid skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-owner-invalid",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner_name/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-owner-invalid", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(invalid github owner) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("uppercase github owner in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-owner-uppercase"), 0o755); err != nil {
			t.Fatalf("mkdir github-owner-uppercase skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-owner-uppercase",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:Owner/repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-owner-uppercase", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(uppercase github owner) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("uppercase github repo in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-uppercase"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-uppercase skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-uppercase",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner/Repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-uppercase", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(uppercase github repo) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("leading-dot github repo in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-leading-dot"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-leading-dot skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-leading-dot",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner/.repo//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-leading-dot", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(leading-dot github repo) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("trailing-dot github repo in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-trailing-dot"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-trailing-dot skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-trailing-dot",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner/repo.//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-trailing-dot", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(trailing-dot github repo) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github repo .git suffix in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-dotgit"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-dotgit skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-dotgit",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner/repo.git//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-dotgit", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github repo .git suffix) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github repo consecutive dots in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-repo-doubledot"), 0o755); err != nil {
			t.Fatalf("mkdir github-repo-doubledot skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-repo-doubledot",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:owner/re..po//skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-repo-doubledot", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github repo consecutive dots) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with @ in path in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-at"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-at skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-at",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@shadow@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-at", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-at) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with : in path in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-colon"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-colon skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-colon",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills:demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-colon", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-colon) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with reserved device path segment in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-reserved-device"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-reserved-device skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-reserved-device",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-reserved-device", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source reserved-device path) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with reserved superscript-device path segment in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-reserved-superscript-device"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-reserved-superscript-device skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-reserved-superscript-device",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-reserved-superscript-device", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source reserved superscript-device path) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with path-segment leading space in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-segment-space"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-segment-space skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-segment-space",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/ demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-segment-space", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-segment-space) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with path-segment trailing dot in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-segment-trailing-dot"), 0o755); err != nil {
			t.Fatalf("mkdir github-path-segment-trailing-dot skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-segment-trailing-dot",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-segment-trailing-dot", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github source path-segment-trailing-dot) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("uppercase github commit sha in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-uppercase"), 0o755); err != nil {
			t.Fatalf("mkdir github uppercase skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-uppercase",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-uppercase", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(uppercase github sha) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with control character in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-control-char"), 0o755); err != nil {
			t.Fatalf("mkdir github control-char skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-control-char",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-control-char", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(control-char github source) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("stdout should include C0/C1 control-character detail, got %q", stdout.String())
		}
	})

	t.Run("github source with C1 control character in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-c1-control-char"), 0o755); err != nil {
			t.Fatalf("mkdir github c1-control-char skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-c1-control-char",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/demo@\u00858f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-c1-control-char", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(c1-control-char github source) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "must not contain C0/C1 control characters") {
			t.Fatalf("stdout should include C0/C1 control-character detail, got %q", stdout.String())
		}
	})

	t.Run("github source path with surrounding spaces in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-path-space"), 0o755); err != nil {
			t.Fatalf("mkdir github path-space skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-path-space",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo// skills/demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-path-space", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(path-space github source) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})

	t.Run("github source with non-canonical path segments in lock is error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-noncanonical-path"), 0o755); err != nil {
			t.Fatalf("mkdir github noncanonical-path skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-noncanonical-path",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills//demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-noncanonical-path", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(non-canonical path github source) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include invalid-source error_code, got %q", stdout.String())
		}
	})
}
