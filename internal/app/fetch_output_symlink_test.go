package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestRunFetchRejectsSymlinkOutputRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	sourceDir := createSkillSourceForInstallTest(t, "fetch-symlink-out")
	deps := fetchDeps{FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
		return sourceDir, nil, nil
	}}

	base := t.TempDir()
	realOut := filepath.Join(base, "real-out")
	if err := os.Mkdir(realOut, 0o755); err != nil {
		t.Fatalf("mkdir real out root: %v", err)
	}
	symlinkOut := filepath.Join(base, "out-link")
	if err := os.Symlink("real-out", symlinkOut); err != nil {
		t.Fatalf("create output root symlink: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runFetchWithDeps([]string{
		"github:org/repo//skills/fetch-symlink-out@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", symlinkOut,
		"--format", "json",
	}, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("runFetch(symlink out) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json errors, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeOutputPrepareFailed+"\"") {
		t.Fatalf("stdout should include output-prepare-failed code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleFetchOutputSymlink+"\"") {
		t.Fatalf("stdout should include symlink rule_id, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runFetchWithDeps([]string{
		"github:org/repo//skills/fetch-symlink-out@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", symlinkOut,
	}, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("runFetch(human symlink out) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for human errors, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), ruleFetchOutputSymlink) {
		t.Fatalf("stderr should include symlink rule marker, got %q", stderr.String())
	}
}

func TestRunFetchRejectsSymlinkOutputEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	sourceDir := createSkillSourceForInstallTest(t, "fetch-symlink-entry")
	deps := fetchDeps{FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
		return sourceDir, nil, nil
	}}

	base := t.TempDir()
	outRoot := filepath.Join(base, "out")
	if err := os.Mkdir(outRoot, 0o755); err != nil {
		t.Fatalf("mkdir out root: %v", err)
	}
	realExisting := filepath.Join(base, "real-existing")
	if err := os.Mkdir(realExisting, 0o755); err != nil {
		t.Fatalf("mkdir real existing dir: %v", err)
	}
	if err := os.Symlink("../real-existing", filepath.Join(outRoot, "fetch-symlink-entry")); err != nil {
		t.Fatalf("create output entry symlink: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runFetchWithDeps([]string{
		"github:org/repo//skills/fetch-symlink-entry@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", outRoot,
		"--format", "json",
	}, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("runFetch(symlink output entry) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json errors, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeCopyFailed+"\"") {
		t.Fatalf("stdout should include copy-failed error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleFetchOutputEntrySymlink+"\"") {
		t.Fatalf("stdout should include output-entry symlink rule_id, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runFetchWithDeps([]string{
		"github:org/repo//skills/fetch-symlink-entry@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", outRoot,
	}, &stdout, &stderr, deps)
	if code != 1 {
		t.Fatalf("runFetch(human symlink output entry) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for human errors, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), ruleFetchOutputEntrySymlink) {
		t.Fatalf("stderr should include output-entry symlink rule marker, got %q", stderr.String())
	}
}
