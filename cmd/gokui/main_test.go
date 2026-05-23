package main

import (
	"bytes"
	"os"
	"os/exec"
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

func TestMainEntrypointVersion(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelperProcess", "--", "version")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"GO_WANT_HELPER_VERSION=v0.2.0",
		"GO_WANT_HELPER_COMMIT=def456",
		"GO_WANT_HELPER_DATE=2026-05-23T00:00:00Z",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\noutput=%s", err, out)
	}

	got := strings.TrimSpace(string(out))
	want := "v0.2.0 (def456, 2026-05-23T00:00:00Z)"
	if !strings.Contains(got, want) {
		t.Fatalf("output = %q, want to include %q", got, want)
	}
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		t.Skip("helper process only")
	}

	version = os.Getenv("GO_WANT_HELPER_VERSION")
	commit = os.Getenv("GO_WANT_HELPER_COMMIT")
	date = os.Getenv("GO_WANT_HELPER_DATE")
	os.Args = []string{"gokui", "version"}
	main()
}
