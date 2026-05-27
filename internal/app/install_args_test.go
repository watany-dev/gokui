package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInstallArgs(t *testing.T) {
	t.Run("parses defaults and flags", func(t *testing.T) {
		got, err := parseInstallArgs([]string{"./skill", "--target", "codex"})
		if err != nil {
			t.Fatalf("parseInstallArgs() error = %v", err)
		}
		if got.Source != "./skill" || got.Target != "codex" || got.Profile != "strict" || got.Format != "human" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
		if got.ProfileSet {
			t.Fatalf("profile should be implicit default, got ProfileSet=true: %+v", got)
		}
	})

	t.Run("parses equals syntax", func(t *testing.T) {
		got, err := parseInstallArgs([]string{"./skill", "--target=custom:/tmp/skills", "--profile=strict", "--format=json"})
		if err != nil {
			t.Fatalf("parseInstallArgs() error = %v", err)
		}
		if got.Target != "custom:/tmp/skills" || got.Format != "json" {
			t.Fatalf("target = %q, want %q", got.Target, "custom:/tmp/skills")
		}
		if !got.ProfileSet {
			t.Fatalf("profile should be explicitly set, got ProfileSet=false: %+v", got)
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		got, err := parseInstallArgs([]string{"./skill", "--target", "codex", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseInstallArgs() error = %v", err)
		}
		if got.Format != "sarif" {
			t.Fatalf("format = %q, want %q", got.Format, "sarif")
		}
	})

	t.Run("parses compact format", func(t *testing.T) {
		got, err := parseInstallArgs([]string{"./skill", "--target", "codex", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseInstallArgs() error = %v", err)
		}
		if got.Format != "compact" {
			t.Fatalf("format = %q, want %q", got.Format, "compact")
		}
	})

	t.Run("parses override options and deduplicates", func(t *testing.T) {
		got, err := parseInstallArgs([]string{
			"./skill",
			"--target", "codex",
			"--override", "PROMPT_OVERRIDE_LANGUAGE",
			"--override=UNPINNED_RUNTIME_TOOL",
			"--override", "PROMPT_OVERRIDE_LANGUAGE",
		})
		if err != nil {
			t.Fatalf("parseInstallArgs() error = %v", err)
		}
		if len(got.Overrides) != 2 {
			t.Fatalf("overrides length = %d, want 2", len(got.Overrides))
		}
		if got.Overrides[0] != "PROMPT_OVERRIDE_LANGUAGE" || got.Overrides[1] != "UNPINNED_RUNTIME_TOOL" {
			t.Fatalf("unexpected overrides: %+v", got.Overrides)
		}
	})

	t.Run("rejects missing values and duplicates", func(t *testing.T) {
		_, err := parseInstallArgs([]string{"./skill", "--target"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --target") {
			t.Fatalf("expected target missing error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./skill", "--target", "codex", "--profile"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --profile") {
			t.Fatalf("expected profile missing error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./a", "./b", "--target", "codex"})
		if err == nil || !strings.Contains(err.Error(), "install accepts exactly one source") {
			t.Fatalf("expected duplicate source error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./skill", "--target", "codex", "--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected format missing error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./skill", "--target", "codex", "--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported install format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./skill", "--target", "codex", "--override"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --override") {
			t.Fatalf("expected missing override value error, got %v", err)
		}

		_, err = parseInstallArgs([]string{"./skill", "--target", "codex", "--override", "bad-id"})
		if err == nil || !strings.Contains(err.Error(), "invalid override rule id") {
			t.Fatalf("expected invalid override rule id error, got %v", err)
		}
	})
}

func TestResolveInstallTarget(t *testing.T) {
	t.Run("codex target uses CODEX_HOME", func(t *testing.T) {
		codexHome := filepath.Join(t.TempDir(), "codex-home")
		t.Setenv("CODEX_HOME", codexHome)
		got, err := resolveInstallTarget("codex")
		if err != nil {
			t.Fatalf("resolveInstallTarget() error = %v", err)
		}
		if got != filepath.Join(codexHome, "skills") {
			t.Fatalf("target = %q", got)
		}
	})

	t.Run("codex target uses home fallback", func(t *testing.T) {
		t.Setenv("CODEX_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		got, err := resolveInstallTarget("codex")
		if err != nil {
			t.Fatalf("resolveInstallTarget() error = %v", err)
		}
		if got != filepath.Join(home, ".codex", "skills") {
			t.Fatalf("target = %q, want under HOME", got)
		}
	})

	t.Run("custom target and invalid targets", func(t *testing.T) {
		customPath := filepath.Join(t.TempDir(), "skills")
		got, err := resolveInstallTarget("custom:" + customPath)
		if err != nil {
			t.Fatalf("resolveInstallTarget(custom) error = %v", err)
		}
		if got != customPath {
			t.Fatalf("custom target = %q", got)
		}

		_, err = resolveInstallTarget("custom:")
		if err == nil || !strings.Contains(err.Error(), "custom target path is required") {
			t.Fatalf("expected empty custom target error, got %v", err)
		}

		_, err = resolveInstallTarget("custom:relative/skills")
		if err == nil || !strings.Contains(err.Error(), "must be absolute") {
			t.Fatalf("expected relative custom target error, got %v", err)
		}

		_, err = resolveInstallTarget("unknown")
		if err == nil || !strings.Contains(err.Error(), "unsupported install target") {
			t.Fatalf("expected unsupported target error, got %v", err)
		}
	})
}

func TestInstallArgExtractionHelpers(t *testing.T) {
	args := []string{"./skill", "--target", "custom:/tmp/skills", "--profile", "strict", "--format", "json"}
	if !installArgsRequestJSON(args) {
		t.Fatal("installArgsRequestJSON() should detect json format")
	}
	if got := extractInstallSourceArg(args); got != "./skill" {
		t.Fatalf("extractInstallSourceArg() = %q", got)
	}
	if got := extractInstallTargetArg(args); got != "custom:/tmp/skills" {
		t.Fatalf("extractInstallTargetArg() = %q", got)
	}
	if got := extractInstallProfileArg(args); got != "strict" {
		t.Fatalf("extractInstallProfileArg() = %q", got)
	}

	if installArgsRequestJSON([]string{"./skill", "--target", "codex"}) {
		t.Fatal("installArgsRequestJSON() should be false without json format")
	}

	equalsArgs := []string{"--target=custom:/tmp/skills", "--profile=team", "--format=json", "./skill"}
	if !installArgsRequestJSON(equalsArgs) {
		t.Fatal("installArgsRequestJSON() should detect --format=json")
	}
	if got := extractInstallSourceArg(equalsArgs); got != "./skill" {
		t.Fatalf("extractInstallSourceArg(equals) = %q", got)
	}
	if got := extractInstallTargetArg(equalsArgs); got != "custom:/tmp/skills" {
		t.Fatalf("extractInstallTargetArg(equals) = %q", got)
	}
	if got := extractInstallProfileArg(equalsArgs); got != "team" {
		t.Fatalf("extractInstallProfileArg(equals) = %q", got)
	}
	if got := extractInstallTargetArg([]string{"./skill"}); got != "" {
		t.Fatalf("extractInstallTargetArg(default) = %q", got)
	}
	if got := extractInstallProfileArg([]string{"./skill"}); got != "strict" {
		t.Fatalf("extractInstallProfileArg(default) = %q", got)
	}
	if installArgsRequestJSON([]string{"./skill", "--target", "codex", "--format", "sarif"}) {
		t.Fatal("installArgsRequestJSON() should be false for non-json format")
	}
	if !installArgsRequestSARIF([]string{"./skill", "--target", "codex", "--format", "sarif"}) {
		t.Fatal("installArgsRequestSARIF() should detect sarif format")
	}
	if !installArgsRequestSARIF([]string{"--target=custom:/tmp/skills", "--profile=strict", "--format=sarif", "./skill"}) {
		t.Fatal("installArgsRequestSARIF() should detect --format=sarif")
	}
	if installArgsRequestSARIF([]string{"./skill", "--target", "codex", "--format", "json"}) {
		t.Fatal("installArgsRequestSARIF() should be false for non-sarif format")
	}
}
