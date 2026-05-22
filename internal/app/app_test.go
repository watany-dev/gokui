package app

import (
	"bytes"
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

	t.Run("inspect command is declared but not implemented", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := Run([]string{"inspect", "./skill"}, &stdout, &stderr, cfg)
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
		if !strings.Contains(gotErr, "command not implemented yet: inspect") {
			t.Fatalf("stderr should include inspect stub message, got %q", gotErr)
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
