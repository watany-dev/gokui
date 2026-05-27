package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunUpdateDryRunLockAndSourceMetadataErrors(t *testing.T) {
	t.Run("unsupported lock policy profile is lockfile error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "unsupported-profile"), 0o755); err != nil {
			t.Fatalf("mkdir unsupported-profile skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unsupported-profile",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Join(targetRoot, "unsupported-profile"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "enterprise", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "unsupported-profile", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(unsupported profile) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lock-invalid error_code, got %q", stdout.String())
		}
	})

	t.Run("non-canonical lock policy profile is lockfile error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "noncanonical-profile"), 0o755); err != nil {
			t.Fatalf("mkdir noncanonical-profile skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "noncanonical-profile",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Join(targetRoot, "noncanonical-profile"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: " Strict ", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "noncanonical-profile", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(noncanonical profile) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lock-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock policy profile must be canonical lowercase without surrounding whitespace") {
			t.Fatalf("stdout should include non-canonical profile message, got %q", stdout.String())
		}
	})

	t.Run("non-canonical lock policy decision is lockfile error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "noncanonical-decision"), 0o755); err != nil {
			t.Fatalf("mkdir noncanonical-decision skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "noncanonical-decision",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Join(targetRoot, "noncanonical-decision"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "PASS"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "noncanonical-decision", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(noncanonical decision) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lock-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock policy decision must be canonical lowercase pass") {
			t.Fatalf("stdout should include non-canonical decision message, got %q", stdout.String())
		}
	})

	t.Run("lock name mismatch is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "name-mismatch"), 0o755); err != nil {
			t.Fatalf("mkdir name-mismatch skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "different-name",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
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
		if err := os.WriteFile(filepath.Join(targetRoot, "name-mismatch", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(lock name mismatch) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock name does not match installed skill directory") {
			t.Fatalf("stdout should include lock-name mismatch message, got %q", stdout.String())
		}
	})

	t.Run("invalid lock installed_at is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "invalid-installed-at"), 0o755); err != nil {
			t.Fatalf("mkdir invalid-installed-at skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "invalid-installed-at",
			InstalledAt: "not-rfc3339",
			Source: lockSource{
				Type:  "local",
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
		if err := os.WriteFile(filepath.Join(targetRoot, "invalid-installed-at", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(invalid installed_at) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock installed_at must be RFC3339") {
			t.Fatalf("stdout should include installed_at message, got %q", stdout.String())
		}
	})

	t.Run("invalid lock severity override is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "invalid-override"), 0o755); err != nil {
			t.Fatalf("mkdir invalid-override skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "invalid-override",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
				SeverityOverrides: []severityOverrideAudit{
					{
						RuleID:            "",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "test",
						ApprovedBy:        "reviewer",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
				},
			},
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
		if err := os.WriteFile(filepath.Join(targetRoot, "invalid-override", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(invalid severity override) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeLockfileInvalid+"\"") {
			t.Fatalf("stdout should include lockfile-invalid error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock policy severity_overrides is invalid") {
			t.Fatalf("stdout should include severity override message, got %q", stdout.String())
		}
	})

	t.Run("mismatched source kind in lock is source-metadata error", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "kind-mismatch"), 0o755); err != nil {
			t.Fatalf("mkdir kind-mismatch skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "kind-mismatch",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: t.TempDir(),
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
		if err := os.WriteFile(filepath.Join(targetRoot, "kind-mismatch", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(mismatched source kind) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include ERROR status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeSourceMetadataBad+"\"") {
			t.Fatalf("stdout should include source-metadata error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "lock source kind does not match source input") {
			t.Fatalf("stdout should include source-kind mismatch message, got %q", stdout.String())
		}
	})

	t.Run("source type mismatch in lock is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "type-mismatch"), 0o755); err != nil {
			t.Fatalf("mkdir type-mismatch skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "type-mismatch",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "archive",
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
		if err := os.WriteFile(filepath.Join(targetRoot, "type-mismatch", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(source type mismatch) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
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
		if !strings.Contains(stdout.String(), "source type mismatch for kind local-dir") {
			t.Fatalf("stdout should include source-type mismatch message, got %q", stdout.String())
		}
	})

	t.Run("github source metadata symlink is source-metadata error with rule_id", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		skillDir := filepath.Join(targetRoot, "github-meta-symlink")
		if err := os.MkdirAll(skillDir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "github-meta-symlink",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "github",
				Input: "github:org/repo//skills/github-meta-symlink@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			Policy: lockPolicy{Profile: "strict", Decision: "pass"},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillDir, installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillDir, "real-source.json"), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write real source metadata: %v", err)
		}
		if err := os.Symlink("real-source.json", filepath.Join(skillDir, sourceMetadataFile)); err != nil {
			t.Fatalf("create source metadata symlink: %v", err)
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runUpdate(source metadata symlink) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+updateCodeSourceMetadataBad+"\"") {
			t.Fatalf("stdout should include source-metadata error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleSourceMetadataSymlink+"\"") {
			t.Fatalf("stdout should include source-metadata symlink rule_id, got %q", stdout.String())
		}
	})

}
