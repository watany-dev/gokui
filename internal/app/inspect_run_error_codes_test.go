package app

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunInspectJSONErrorCodes(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	t.Run("parse error emits args-invalid code", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), inspectErrorCodeArgsInvalid) {
			t.Fatalf("stdout should include %q, got %q", inspectErrorCodeArgsInvalid, stdout.String())
		}
	})

	t.Run("human mode source-not-found writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "./does-not-exist"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "inspect source not found") {
			t.Fatalf("stderr should include source-not-found, got %q", stderr.String())
		}
	})

	t.Run("source stat access error emits source-prepare-failed code", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		base := t.TempDir()
		locked := filepath.Join(base, "locked")
		if err := os.Mkdir(locked, 0o755); err != nil {
			t.Fatalf("mkdir locked dir: %v", err)
		}
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatalf("chmod locked dir: %v", err)
		}
		defer os.Chmod(locked, 0o755)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", filepath.Join(locked, "skill"), "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), inspectErrorCodeSourcePrepareFailed) {
			t.Fatalf("stdout should include %q, got %q", inspectErrorCodeSourcePrepareFailed, stdout.String())
		}
	})

	t.Run("local scan failure emits scan-failed code", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "inspect-local-scan-fail")
		refDir := filepath.Join(skillRoot, "references")
		if err := os.Mkdir(refDir, 0o755); err != nil {
			t.Fatalf("mkdir references: %v", err)
		}
		blocked := filepath.Join(refDir, "blocked.md")
		if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", skillRoot, "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), inspectErrorCodeScanFailed) {
			t.Fatalf("stdout should include %q, got %q", inspectErrorCodeScanFailed, stdout.String())
		}
	})

	t.Run("local scan special-file failure emits wrapped rule_id", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "inspect-local-special-file")
		fifoPath := filepath.Join(skillRoot, "pipe.fifo")
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo command not available")
		}
		if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
			t.Skipf("mkfifo unsupported in this environment: %v", err)
		}

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", skillRoot, "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeScanFailed+"\"") {
			t.Fatalf("stdout should include scan-failed code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"SPECIAL_FILE_IN_SCAN_SOURCE\"") {
			t.Fatalf("stdout should include wrapped scan special-file rule_id, got %q", stdout.String())
		}
	})

	t.Run("ancestor symlink source path emits prepare-failed with rule_id", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "json-ancestor-skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, "SKILL.md"), []byte("---\nname: json-ancestor-skill\ndescription: Use when testing inspect json rule_id on ancestor symlink.\n---\n"), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}
		inspectPath := filepath.Join(linkParent, "json-ancestor-skill")

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", inspectPath, "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeSourcePrepareFailed+"\"") {
			t.Fatalf("stdout should include source-prepare-failed code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleInspectSourceSymlink+"\"") {
			t.Fatalf("stdout should include source symlink rule_id, got %q", stdout.String())
		}
	})

	t.Run("local scan failure in human mode writes stderr", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "inspect-local-scan-fail-human")
		refDir := filepath.Join(skillRoot, "references")
		if err := os.Mkdir(refDir, 0o755); err != nil {
			t.Fatalf("mkdir references: %v", err)
		}
		blocked := filepath.Join(refDir, "blocked.md")
		if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", skillRoot}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "failed to read scan file") {
			t.Fatalf("stderr should include scan failure, got %q", stderr.String())
		}
	})

	t.Run("github scan failure emits scan-failed code", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "inspect-github-scan-fail")
		refDir := filepath.Join(skillRoot, "references")
		if err := os.Mkdir(refDir, 0o755); err != nil {
			t.Fatalf("mkdir references: %v", err)
		}
		blocked := filepath.Join(refDir, "blocked.md")
		if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runInspectWithDeps(
			[]string{"github:org/repo//skills/inspect-github-scan-fail@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"},
			&stdout,
			&stderr,
			inspectDeps{
				PrepareEvaluationSource: func(input string, sourceKind string) (string, func(), error) {
					return skillRoot, nil, nil
				},
			},
		)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), inspectErrorCodeScanFailed) {
			t.Fatalf("stdout should include %q, got %q", inspectErrorCodeScanFailed, stdout.String())
		}
	})

	t.Run("github scan special-file failure emits wrapped rule_id", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "inspect-github-special-file")
		fifoPath := filepath.Join(skillRoot, "pipe.fifo")
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo command not available")
		}
		if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
			t.Skipf("mkfifo unsupported in this environment: %v", err)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runInspectWithDeps(
			[]string{"github:org/repo//skills/inspect-github-special-file@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"},
			&stdout,
			&stderr,
			inspectDeps{
				PrepareEvaluationSource: func(input string, sourceKind string) (string, func(), error) {
					return skillRoot, nil, nil
				},
			},
		)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+inspectErrorCodeScanFailed+"\"") {
			t.Fatalf("stdout should include scan-failed code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"SPECIAL_FILE_IN_SCAN_SOURCE\"") {
			t.Fatalf("stdout should include wrapped scan special-file rule_id, got %q", stdout.String())
		}
	})

	t.Run("github invalid syntax in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo/path@main"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error, got %q", stderr.String())
		}
	})

	t.Run("github uppercase commit sha in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for uppercase sha, got %q", stderr.String())
		}
	})

	t.Run("github source with control character in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for control-char input, got %q", stderr.String())
		}
	})

	t.Run("github source with unicode whitespace in ref in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for ref-unicode-whitespace input, got %q", stderr.String())
		}
	})

	t.Run("github source with zero-width char in ref in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for ref-zero-width input, got %q", stderr.String())
		}
	})

	t.Run("github source with bidi control in ref in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for ref-bidi-control input, got %q", stderr.String())
		}
	})

	t.Run("github source with unicode whitespace in owner in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:or\u00a0g/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for owner-unicode-whitespace input, got %q", stderr.String())
		}
	})

	t.Run("github source with zero-width char in repo in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/re\u200bpo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo-zero-width input, got %q", stderr.String())
		}
	})

	t.Run("github source with unicode tag in owner in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:or\U000E0001g/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for owner-unicode-tag input, got %q", stderr.String())
		}
	})

	t.Run("github source with variation selector in repo in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/re\ufe0fpo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo-variation-selector input, got %q", stderr.String())
		}
	})

	t.Run("github source with @ in path in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean@skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-at input, got %q", stderr.String())
		}
	})

	t.Run("github source with : in path in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills:clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-colon input, got %q", stderr.String())
		}
	})

	t.Run("github source with Windows reserved path segment in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for reserved-device path input, got %q", stderr.String())
		}
	})

	t.Run("github source with Windows superscript reserved path segment in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for reserved superscript-device path input, got %q", stderr.String())
		}
	})

	t.Run("github source with bidi control in path in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-bidi-control input, got %q", stderr.String())
		}
	})

	t.Run("github source with zero-width char in path in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-zero-width input, got %q", stderr.String())
		}
	})

	t.Run("github source with whitespace char in path in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-whitespace input, got %q", stderr.String())
		}
	})

	t.Run("github source with path segment leading space in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/ clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-segment-space input, got %q", stderr.String())
		}
	})

	t.Run("github source with path segment trailing dot in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-segment-trailing-dot input, got %q", stderr.String())
		}
	})

	t.Run("github source with path surrounding spaces in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo// skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for path-space input, got %q", stderr.String())
		}
	})

	t.Run("github source with non-canonical path segments in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills//clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for non-canonical path input, got %q", stderr.String())
		}
	})

	t.Run("github source with invalid owner format in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner_name/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for invalid owner format, got %q", stderr.String())
		}
	})

	t.Run("github source with uppercase owner in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:Owner/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for uppercase owner, got %q", stderr.String())
		}
	})

	t.Run("github source with uppercase repo in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner/Repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for uppercase repo, got %q", stderr.String())
		}
	})

	t.Run("github source with repo leading dot in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner/.repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo leading dot, got %q", stderr.String())
		}
	})

	t.Run("github source with repo trailing dot in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner/repo.//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo trailing dot, got %q", stderr.String())
		}
	})

	t.Run("github source with repo .git suffix in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner/repo.git//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo .git suffix, got %q", stderr.String())
		}
	})

	t.Run("github source with repo consecutive dots in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:owner/re..po//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "invalid github source") {
			t.Fatalf("stderr should include github source error for repo consecutive dots, got %q", stderr.String())
		}
	})

	t.Run("github floating ref in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := Run([]string{"inspect", "github:org/repo//skills/clean-skill@main"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "requires a commit-pinned ref") {
			t.Fatalf("stderr should include commit pin requirement, got %q", stderr.String())
		}
	})

	t.Run("github fetch failure in human mode writes stderr", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := runInspectWithDeps(
			[]string{"github:org/repo//skills/clean-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"},
			&stdout,
			&stderr,
			inspectDeps{
				PrepareEvaluationSource: func(input string, sourceKind string) (string, func(), error) {
					return "", nil, os.ErrNotExist
				},
			},
		)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if stderr.Len() == 0 {
			t.Fatal("stderr should include fetch error")
		}
	})
}
