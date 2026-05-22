package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionUsesBuildVars(t *testing.T) {
	prevVersion, prevCommit, prevDate := version, commit, date
	t.Cleanup(func() {
		version = prevVersion
		commit = prevCommit
		date = prevDate
	})

	version = "v0.1.0"
	commit = "abc123"
	date = "2026-05-22T00:00:00Z"

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, want 0", code)
	}

	got := strings.TrimSpace(stdout.String())
	want := "v0.1.0 (abc123, 2026-05-22T00:00:00Z)"
	if got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"unknown-cmd"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}

	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "unknown command: unknown-cmd") {
		t.Fatalf("stderr should include unknown command, got %q", stderr.String())
	}
}
