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

		code := Run([]string{"inspect", "./skill"}, &stdout, &stderr, cfg)
		if code != 1 {
			t.Fatalf("Run() code = %d, want 1", code)
		}

		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty, got %q", stdout.String())
		}

		gotErr := stderr.String()
		if !strings.Contains(gotErr, "unknown command: inspect ./skill") {
			t.Fatalf("stderr should include unknown command, got %q", gotErr)
		}
		if !strings.Contains(gotErr, usage()) {
			t.Fatalf("stderr should include usage, got %q", gotErr)
		}
	})
}
