package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUpdateDryRunSourceLockValidationErrors(t *testing.T) {
	t.Run("unsupported source kind in lock is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "unknown-kind"), 0o755); err != nil {
			t.Fatalf("mkdir unknown-kind skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unknown-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "weird-kind",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "unknown-kind", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(unsupported source kind) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "unsupported source kind in lockfile") {
			t.Fatalf("stdout should include unsupported-source-kind message, got %q", stdout.String())
		}
	})

	t.Run("source input with surrounding whitespace is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "input-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir input-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "input-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: " " + t.TempDir() + " ",
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "input-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(input whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source input must not contain leading or trailing whitespace") {
			t.Fatalf("stdout should include input-whitespace message, got %q", stdout.String())
		}
	})

	t.Run("source input must be canonical cleaned path for local-dir", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "input-noncanonical"), 0o755); err != nil {
			t.Fatalf("mkdir input-noncanonical skill dir: %v", err)
		}
		base := t.TempDir()
		nonCanonical := base + "/a/../a"
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "input-noncanonical",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: nonCanonical,
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "input-noncanonical", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(input noncanonical) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source input must be a canonical cleaned path for local/archive sources") {
			t.Fatalf("stdout should include noncanonical input message, got %q", stdout.String())
		}
	})

	t.Run("source kind with surrounding whitespace is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "kind-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir kind-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "kind-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  " local-dir ",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "kind-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(kind whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source kind must not contain leading or trailing whitespace") {
			t.Fatalf("stdout should include kind-whitespace message, got %q", stdout.String())
		}
	})

	t.Run("source kind with uppercase letters is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "kind-uppercase"), 0o755); err != nil {
			t.Fatalf("mkdir kind-uppercase skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "kind-uppercase",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "LOCAL-DIR",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "kind-uppercase", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(kind uppercase) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source kind must be canonical lowercase") {
			t.Fatalf("stdout should include kind-lowercase message, got %q", stdout.String())
		}
	})

	t.Run("source type with surrounding whitespace is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "type-whitespace"), 0o755); err != nil {
			t.Fatalf("mkdir type-whitespace skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "type-whitespace",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  " local ",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "type-whitespace", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(type whitespace) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source type must not contain leading or trailing whitespace") {
			t.Fatalf("stdout should include type-whitespace message, got %q", stdout.String())
		}
	})

	t.Run("source type with uppercase letters is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "type-uppercase"), 0o755); err != nil {
			t.Fatalf("mkdir type-uppercase skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "type-uppercase",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "LOCAL",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "type-uppercase", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(type uppercase) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source type must be canonical lowercase") {
			t.Fatalf("stdout should include type-lowercase message, got %q", stdout.String())
		}
	})

	t.Run("github source input must be canonical", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "github-noncanonical"), 0o755); err != nil {
			t.Fatalf("mkdir github-noncanonical skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-noncanonical",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/./demo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "github-noncanonical", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(github noncanonical) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeGitHubSourceBad+"\"") {
			t.Fatalf("stdout should include github-source-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "invalid github source in lockfile") {
			t.Fatalf("stdout should include invalid github source message, got %q", stdout.String())
		}
	})
}
