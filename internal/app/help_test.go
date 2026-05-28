package app

import (
	"bytes"
	"strings"
	"testing"
)

func runForTest(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr, Config{Version: "test", Commit: "test", Date: "test"})
	return stdout.String(), stderr.String(), code
}

func TestHelpTopLevel(t *testing.T) {
	cases := [][]string{
		{"help"},
		{"--help"},
		{"-h"},
		{"help", "--help"},
		{"help", "-h"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			stdout, stderr, code := runForTest(t, args...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			if stderr != "" {
				t.Fatalf("stderr should be empty, got %q", stderr)
			}
			for _, want := range []string{"Commands:", "fetch", "inspect", "vet", "install", "update", "lock verify"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q\n--- stdout ---\n%s", want, stdout)
				}
			}
		})
	}
}

func TestHelpPerCommand(t *testing.T) {
	cases := []struct {
		args     []string
		mustHave []string
	}{
		{[]string{"help", "version"}, []string{"gokui version", "Exit codes:"}},
		{[]string{"help", "fetch"}, []string{"gokui fetch", "--out", "--format", "github:owner/repo"}},
		{[]string{"help", "inspect"}, []string{"gokui inspect", "--format", "review-json"}},
		{[]string{"help", "vet"}, []string{"gokui vet", "--profile", "strict"}},
		{[]string{"help", "install"}, []string{"gokui install", "--target", "--profile", "--override"}},
		{[]string{"help", "update"}, []string{"gokui update", "--dry-run", "--target"}},
		{[]string{"help", "lock", "verify"}, []string{"gokui lock verify", "gokui.lock"}},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			stdout, stderr, code := runForTest(t, tc.args...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
			}
			if stderr != "" {
				t.Fatalf("stderr should be empty, got %q", stderr)
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q\n--- stdout ---\n%s", want, stdout)
				}
			}
		})
	}
}

func TestHelpUnknownCommand(t *testing.T) {
	stdout, stderr, code := runForTest(t, "help", "bogus")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout should be empty, got %q", stdout)
	}
	if !strings.Contains(stderr, "unknown command: bogus") {
		t.Fatalf("stderr missing unknown-command message, got %q", stderr)
	}
	if !strings.Contains(stderr, "Commands:") {
		t.Fatalf("stderr missing top-level help, got %q", stderr)
	}
}

func TestPerCommandHelpFlag(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		mustHave string
	}{
		{"fetch_help", []string{"fetch", "--help"}, "gokui fetch"},
		{"fetch_h", []string{"fetch", "-h"}, "gokui fetch"},
		{"inspect_help", []string{"inspect", "--help"}, "gokui inspect"},
		{"vet_help", []string{"vet", "--help"}, "gokui vet"},
		{"version_help", []string{"version", "--help"}, "gokui version"},
		{"install_help_no_required_flags", []string{"install", "--help"}, "gokui install"},
		{"install_help_with_other_args", []string{"install", "/some/path", "--help"}, "gokui install"},
		{"update_help", []string{"update", "--help"}, "gokui update"},
		{"lock_verify_help", []string{"lock", "verify", "--help"}, "gokui lock verify"},
		{"lock_help", []string{"lock", "--help"}, "gokui lock verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runForTest(t, tc.args...)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr)
			}
			if stderr != "" {
				t.Fatalf("stderr should be empty, got %q", stderr)
			}
			if !strings.Contains(stdout, tc.mustHave) {
				t.Errorf("stdout missing %q\n--- stdout ---\n%s", tc.mustHave, stdout)
			}
		})
	}
}

func TestInstallHelpDoesNotTriggerArgsInvalid(t *testing.T) {
	stdout, stderr, code := runForTest(t, "install", "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.Contains(stdout, "INSTALL_ARGS_INVALID") || strings.Contains(stderr, "INSTALL_ARGS_INVALID") {
		t.Fatalf("help flag must not run install parser; got stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestVersionRejectsExtraArgs(t *testing.T) {
	stdout, stderr, code := runForTest(t, "version", "foo")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout should be empty, got %q", stdout)
	}
	if !strings.Contains(stderr, "unknown command: version foo") {
		t.Fatalf("stderr missing unknown-command message, got %q", stderr)
	}
}

func TestNoArgsStillErrors(t *testing.T) {
	stdout, stderr, code := runForTest(t)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout should be empty, got %q", stdout)
	}
	if !strings.Contains(stderr, "gokui") {
		t.Fatalf("stderr missing usage, got %q", stderr)
	}
}

func TestHasHelpFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"foo"}, false},
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"foo", "--help", "bar"}, true},
		{[]string{"foo", "-h"}, true},
		{[]string{"--helpme"}, false},
	}
	for _, tc := range cases {
		got := hasHelpFlag(tc.args)
		if got != tc.want {
			t.Errorf("hasHelpFlag(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
