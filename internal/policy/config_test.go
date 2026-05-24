package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadUserPolicy(t *testing.T) {
	t.Run("missing file returns found false", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "missing-policy.toml")
		t.Setenv(envPolicyPath, p)
		cfg, found, err := LoadUserPolicy()
		if err != nil {
			t.Fatalf("LoadUserPolicy() error = %v", err)
		}
		if found {
			t.Fatal("expected found=false for missing file")
		}
		if cfg.DefaultProfile != "" {
			t.Fatalf("default profile = %q, want empty", cfg.DefaultProfile)
		}
	})

	t.Run("loads default profile and normalizes casing", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(p, []byte("default_profile = \" Research \"\n[overrides]\nallowed_rule_ids = [\" prompt_override_language \", \"UNPINNED_RUNTIME_TOOL\", \"PROMPT_OVERRIDE_LANGUAGE\"]\n"), 0o644); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		t.Setenv(envPolicyPath, p)
		cfg, found, err := LoadUserPolicy()
		if err != nil {
			t.Fatalf("LoadUserPolicy() error = %v", err)
		}
		if !found {
			t.Fatal("expected found=true")
		}
		if cfg.DefaultProfile != "research" {
			t.Fatalf("default profile = %q, want research", cfg.DefaultProfile)
		}
		if !cfg.Overrides.Enabled {
			t.Fatal("overrides.enabled default should be true")
		}
		if len(cfg.Overrides.AllowedRuleIDs) != 2 {
			t.Fatalf("allowed_rule_ids length = %d, want 2", len(cfg.Overrides.AllowedRuleIDs))
		}
		if cfg.Overrides.AllowedRuleIDs[0] != "PROMPT_OVERRIDE_LANGUAGE" || cfg.Overrides.AllowedRuleIDs[1] != "UNPINNED_RUNTIME_TOOL" {
			t.Fatalf("allowed_rule_ids normalization mismatch: %+v", cfg.Overrides.AllowedRuleIDs)
		}
	})

	t.Run("rejects unknown keys", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(p, []byte("default_profile = \"strict\"\nfoo = 1\n"), 0o644); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		t.Setenv(envPolicyPath, p)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "unknown policy keys") {
			t.Fatalf("expected unknown key error, got %v", err)
		}
	})

	t.Run("rejects invalid toml", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(p, []byte("default_profile = ["), 0o644); err != nil {
			t.Fatalf("write policy file: %v", err)
		}
		t.Setenv(envPolicyPath, p)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "failed to parse policy file") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("rejects too-large policy file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "policy.toml")
		tooLarge := strings.Repeat("a", maxPolicyBytes+1)
		if err := os.WriteFile(p, []byte(tooLarge), 0o644); err != nil {
			t.Fatalf("write large policy file: %v", err)
		}
		t.Setenv(envPolicyPath, p)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
			t.Fatalf("expected max size error, got %v", err)
		}
	})

	t.Run("rejects non-regular policy file", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(envPolicyPath, dir)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("expected regular file error, got %v", err)
		}
	})

	t.Run("returns read error for unreadable policy file", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission semantics differ on windows")
		}
		p := filepath.Join(t.TempDir(), "policy.toml")
		if err := os.WriteFile(p, []byte(`default_profile = "strict"`), 0o000); err != nil {
			t.Fatalf("write unreadable policy file: %v", err)
		}
		t.Setenv(envPolicyPath, p)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "failed to read policy file") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("rejects symlink policy path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		dir := t.TempDir()
		target := filepath.Join(dir, "policy.toml")
		if err := os.WriteFile(target, []byte(`default_profile = "strict"`), 0o644); err != nil {
			t.Fatalf("write target policy file: %v", err)
		}
		link := filepath.Join(dir, "policy-link.toml")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		t.Setenv(envPolicyPath, link)
		_, _, err := LoadUserPolicy()
		if err == nil || !strings.Contains(err.Error(), "must not contain symlink component") {
			t.Fatalf("expected symlink component error, got %v", err)
		}
	})
}

func TestResolvePolicyPath(t *testing.T) {
	t.Run("uses env override when provided", func(t *testing.T) {
		override := filepath.Join(t.TempDir(), "override.toml")
		t.Setenv(envPolicyPath, override)
		got, err := resolvePolicyPath()
		if err != nil {
			t.Fatalf("resolvePolicyPath() error = %v", err)
		}
		if got != filepath.Clean(override) {
			t.Fatalf("path = %q, want %q", got, filepath.Clean(override))
		}
	})

	t.Run("falls back to home config path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv(envPolicyPath, "")
		got, err := resolvePolicyPath()
		if err != nil {
			t.Fatalf("resolvePolicyPath() error = %v", err)
		}
		want := filepath.Join(home, defaultPolicyRel)
		if got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
	})

	t.Run("returns error when home is unavailable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("home resolution semantics differ on windows")
		}
		t.Setenv(envPolicyPath, "")
		t.Setenv("HOME", "")
		_, err := resolvePolicyPath()
		if err == nil || !strings.Contains(err.Error(), "failed to resolve home directory") {
			t.Fatalf("expected home resolution error, got %v", err)
		}
	})
}

func TestRejectSymlinkPath(t *testing.T) {
	t.Run("returns permission error for unreadable path component", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission semantics differ on windows")
		}
		root := t.TempDir()
		blocked := filepath.Join(root, "blocked")
		if err := os.Mkdir(blocked, 0o000); err != nil {
			t.Fatalf("mkdir blocked: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
		err := rejectSymlinkPath(filepath.Join(blocked, "child", "policy.toml"))
		if err == nil || !strings.Contains(err.Error(), "failed to validate policy path component") {
			t.Fatalf("expected path validation error, got %v", err)
		}
	})
}
