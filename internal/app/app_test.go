package app

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildVersionString(t *testing.T) {
	t.Run("uses configured values", func(t *testing.T) {
		cfg := Config{
			Version: "v0.1.0",
			Commit:  "abc123",
			Date:    "2026-05-22T00:00:00Z",
		}

		got := BuildVersionString(cfg)
		want := "v0.1.0 (abc123, 2026-05-22T00:00:00Z)"
		if got != want {
			t.Fatalf("BuildVersionString() = %q, want %q", got, want)
		}
	})

	t.Run("fills defaults", func(t *testing.T) {
		got := BuildVersionString(Config{})
		want := "dev (none, unknown)"
		if got != want {
			t.Fatalf("BuildVersionString() = %q, want %q", got, want)
		}
	})
}

func TestRun(t *testing.T) {
	cfg := Config{
		Version: "v0.1.0",
		Commit:  "abc123",
		Date:    "2026-05-22T00:00:00Z",
	}

	t.Run("version command", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"version"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}

		got := strings.TrimSpace(stdout.String())
		want := "v0.1.0 (abc123, 2026-05-22T00:00:00Z)"
		if got != want {
			t.Fatalf("stdout = %q, want %q", got, want)
		}

		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
	})

	t.Run("no args", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run(nil, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := strings.TrimSpace(stderr.String())
		if gotErr != usage() {
			t.Fatalf("stderr = %q, want %q", gotErr, usage())
		}
	})

	t.Run("unknown command", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"nope", "./skill"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "unknown command: nope ./skill") {
			t.Fatalf("stderr should include unknown command, got %q", gotErr)
		}
		if !strings.Contains(gotErr, usage()) {
			t.Fatalf("stderr should include usage, got %q", gotErr)
		}
	})

	t.Run("inspect json emits stable pre-release report", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		fixturePath := filepath.FromSlash("../../fixtures/clean-skill")
		code := Run([]string{"inspect", fixturePath, "--format", "json"}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}

		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		var got inspectReport
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatalf("inspect json should be valid: %v\nstdout=%q", err, stdout.String())
		}

		if got.SchemaVersion != "0.1.0-draft" {
			t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, "0.1.0-draft")
		}
		if !got.PreRelease {
			t.Fatalf("pre_release = false, want true")
		}
		if got.Source.Input != fixturePath {
			t.Fatalf("source.input = %q, want %q", got.Source.Input, fixturePath)
		}
		if got.Source.Kind != "local-dir" {
			t.Fatalf("source.kind = %q, want %q", got.Source.Kind, "local-dir")
		}
		if got.Decision != "PRE_RELEASE_STUB" {
			t.Fatalf("decision = %q, want %q", got.Decision, "PRE_RELEASE_STUB")
		}
		if len(got.Findings) != 0 {
			t.Fatalf("findings length = %d, want 0", len(got.Findings))
		}
		if got.Note != "inspect pipeline is not implemented yet" {
			t.Fatalf("note = %q, want %q", got.Note, "inspect pipeline is not implemented yet")
		}
	})

	t.Run("inspect requires source", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"inspect", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "inspect source is required") {
			t.Fatalf("stderr should include argument error, got %q", stderr.String())
		}
	})

	t.Run("inspect rejects unknown option", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"inspect", "../../fixtures/clean-skill", "--badopt"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "unknown inspect option: --badopt") {
			t.Fatalf("stderr should include option error, got %q", stderr.String())
		}
	})

	t.Run("inspect rejects unsupported format", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"inspect", "../../fixtures/clean-skill", "--format", "xml"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "unsupported inspect format: xml") {
			t.Fatalf("stderr should include format error, got %q", stderr.String())
		}
	})

	t.Run("inspect fails when source is missing on disk", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"inspect", "./does-not-exist", "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "inspect source not found: ./does-not-exist") {
			t.Fatalf("stderr should include source-not-found, got %q", stderr.String())
		}
	})

	t.Run("inspect human format prints summary", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		fixturePath := filepath.FromSlash("../../fixtures/clean-skill")
		code := Run([]string{"inspect", fixturePath}, &stdout, &stderr, cfg)
		if code != 0 {
			t.Fatalf("Run() code = %d, want 0", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "gokui is pre-release: inspect pipeline is not implemented yet") {
			t.Fatalf("stdout should include pre-release summary, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "source: "+fixturePath+" (local-dir)") {
			t.Fatalf("stdout should include source summary, got %q", stdout.String())
		}
	})

	t.Run("inspect rejects local dir without root SKILL.md", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		fixturePath := filepath.FromSlash("../../fixtures/no-root-skill")
		code := Run([]string{"inspect", fixturePath, "--format", "json"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "inspect local dir must contain SKILL.md at root") {
			t.Fatalf("stderr should include missing root SKILL.md, got %q", stderr.String())
		}
	})

	t.Run("inspect rejects local source when path is a file", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		fixturePath := filepath.FromSlash("../../fixtures/no-root-skill/README.md")
		code := Run([]string{"inspect", fixturePath}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "inspect local source must be a directory") {
			t.Fatalf("stderr should include not-directory error, got %q", stderr.String())
		}
	})

	t.Run("install command is declared but not implemented", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"install", "./skill", "--target", "codex"}, &stdout, &stderr, cfg)
		if code != 2 {
			t.Fatalf("Run() code = %d, want 2", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "pre-release") {
			t.Fatalf("stderr should include pre-release warning, got %q", gotErr)
		}
		if !strings.Contains(gotErr, "command not implemented yet: install") {
			t.Fatalf("stderr should include install stub message, got %q", gotErr)
		}
	})

	t.Run("update command is declared but not implemented", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"update", "--dry-run"}, &stdout, &stderr, cfg)
		if code != 2 {
			t.Fatalf("Run() code = %d, want 2", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "pre-release") {
			t.Fatalf("stderr should include pre-release warning, got %q", gotErr)
		}
		if !strings.Contains(gotErr, "command not implemented yet: update") {
			t.Fatalf("stderr should include update stub message, got %q", gotErr)
		}
	})

	t.Run("lock verify is declared but not implemented", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"lock", "verify"}, &stdout, &stderr, cfg)
		if code != 2 {
			t.Fatalf("Run() code = %d, want 2", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "pre-release") {
			t.Fatalf("stderr should include pre-release warning, got %q", gotErr)
		}
		if !strings.Contains(gotErr, "command not implemented yet: lock verify") {
			t.Fatalf("stderr should include lock verify stub message, got %q", gotErr)
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

func TestParseInspectArgs(t *testing.T) {
	t.Run("parses source and default format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" {
			t.Fatalf("input = %q, want %q", input, "./skill")
		}
		if format != "human" {
			t.Fatalf("format = %q, want %q", format, "human")
		}
	})

	t.Run("parses equals format", func(t *testing.T) {
		input, format, err := parseInspectArgs([]string{"./skill", "--format=json"})
		if err != nil {
			t.Fatalf("parseInspectArgs() error = %v", err)
		}
		if input != "./skill" || format != "json" {
			t.Fatalf("got (%q, %q), want (%q, %q)", input, format, "./skill", "json")
		}
	})

	t.Run("errors when format value is missing", func(t *testing.T) {
		_, _, err := parseInspectArgs([]string{"./skill", "--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected missing format error, got %v", err)
		}
	})

	t.Run("errors when more than one source is given", func(t *testing.T) {
		_, _, err := parseInspectArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "inspect accepts exactly one source") {
			t.Fatalf("expected single source error, got %v", err)
		}
	})
}

func TestDetectSourceKind(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "github:org/repo//skills/x@abc123", want: "github-source"},
		{in: "./skill.zip", want: "zip"},
		{in: "./skill.tgz", want: "tar"},
		{in: "./skill.tar.gz", want: "tar"},
		{in: "./skill", want: "local-dir"},
	}

	for _, tc := range cases {
		if got := detectSourceKind(tc.in); got != tc.want {
			t.Fatalf("detectSourceKind(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
