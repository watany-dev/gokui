package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFakeSubmake(t *testing.T, failVuln bool) string {
	t.Helper()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "fake-submake.sh")
	failLine := "exit 0"
	if failVuln {
		failLine = "exit 17"
	}

	script := `#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
shift || true
block_cleanup="${FAKE_BLOCK_CLEANUP:-0}"

build_out=""
sarif_out=""
for arg in "$@"; do
	case "$arg" in
		BUILD_OUT=*)
			build_out="${arg#BUILD_OUT=}"
			;;
		INSPECT_SARIF_OUT=*)
			sarif_out="${arg#INSPECT_SARIF_OUT=}"
			;;
	esac
done

case "$target" in
	check|test|test-race)
		exit 0
		;;
	build)
		mkdir -p "$(dirname "$build_out")"
		: > "$build_out"
		if [ "$block_cleanup" = "1" ]; then
			chmod 0555 "$(dirname "$build_out")"
		fi
		exit 0
		;;
	inspect-sarif)
		mkdir -p "$(dirname "$sarif_out")"
		: > "$sarif_out"
		if [ "$block_cleanup" = "1" ]; then
			chmod 0555 "$(dirname "$sarif_out")"
		fi
		exit 0
		;;
	vuln)
		` + failLine + `
		;;
	*)
		exit 0
		;;
esac
`

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake submake: %v", err)
	}
	return path
}

func runReleaseCheck(t *testing.T, fakeMake, buildOut, sarifOut string, withVuln bool, blockCleanup bool) (int, string) {
	t.Helper()

	vuln := "0"
	if withVuln {
		vuln = "1"
	}
	block := "0"
	if blockCleanup {
		block = "1"
	}

	cmd := exec.Command(
		"make",
		"-f", "../../Makefile",
		"release-check",
		"MAKE="+fakeMake,
		"RELEASE_CHECK_BUILD_OUT="+buildOut,
		"RELEASE_CHECK_SARIF_OUT="+sarifOut,
		"RELEASE_CHECK_VULN="+vuln,
		"FAKE_BLOCK_CLEANUP="+block,
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if !strings.Contains(err.Error(), "exit status") || !errorsAs(err, &exitErr) {
		t.Fatalf("release-check execution error: %v\noutput:\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

func errorsAs(err error, target **exec.ExitError) bool {
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	*target = exitErr
	return true
}

func TestReleaseCheckCleansArtifactsOnSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check shell contract is exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	buildOut := filepath.Join(tmp, "release-build")
	sarifOut := filepath.Join(tmp, "inspect.sarif")
	fakeMake := writeFakeSubmake(t, false)

	exitCode, out := runReleaseCheck(t, fakeMake, buildOut, sarifOut, false, false)
	if exitCode != 0 {
		t.Fatalf("expected zero exit from release-check success path, got %d\noutput:\n%s", exitCode, out)
	}
	if _, err := os.Stat(buildOut); !os.IsNotExist(err) {
		t.Fatalf("expected release-check cleanup to remove build artifact, stat err=%v", err)
	}
	if _, err := os.Stat(sarifOut); !os.IsNotExist(err) {
		t.Fatalf("expected release-check cleanup to remove SARIF artifact, stat err=%v", err)
	}
}

func TestReleaseCheckCleansArtifactsOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check shell contract is exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	buildOut := filepath.Join(tmp, "release-build")
	sarifOut := filepath.Join(tmp, "inspect.sarif")
	fakeMake := writeFakeSubmake(t, true)

	exitCode, out := runReleaseCheck(t, fakeMake, buildOut, sarifOut, true, false)
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit from release-check failure path\noutput:\n%s", out)
	}
	if _, err := os.Stat(buildOut); !os.IsNotExist(err) {
		t.Fatalf("expected release-check cleanup to remove build artifact after failure, stat err=%v", err)
	}
	if _, err := os.Stat(sarifOut); !os.IsNotExist(err) {
		t.Fatalf("expected release-check cleanup to remove SARIF artifact after failure, stat err=%v", err)
	}
}

func TestReleaseCheckFailsClosedWhenCleanupRemovalFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check shell contract is exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	buildDir := filepath.Join(tmp, "build-dir")
	sarifDir := filepath.Join(tmp, "sarif-dir")
	buildOut := filepath.Join(buildDir, "release-build")
	sarifOut := filepath.Join(sarifDir, "inspect.sarif")
	fakeMake := writeFakeSubmake(t, false)
	t.Cleanup(func() {
		_ = os.Chmod(buildDir, 0o755)
		_ = os.Chmod(sarifDir, 0o755)
	})

	exitCode, out := runReleaseCheck(t, fakeMake, buildOut, sarifOut, false, true)
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when cleanup removal fails\noutput:\n%s", out)
	}
	if !strings.Contains(out, "release-check cleanup failed for output path: "+buildOut) {
		t.Fatalf("expected cleanup failure message for build output path, got:\n%s", out)
	}
	if !strings.Contains(out, "release-check cleanup failed for output path: "+sarifOut) {
		t.Fatalf("expected cleanup failure message for SARIF output path, got:\n%s", out)
	}
	if _, err := os.Stat(buildOut); err != nil {
		t.Fatalf("expected build artifact to remain when cleanup fails, stat err=%v", err)
	}
	if _, err := os.Stat(sarifOut); err != nil {
		t.Fatalf("expected SARIF artifact to remain when cleanup fails, stat err=%v", err)
	}
}
