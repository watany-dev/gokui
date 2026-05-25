package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runReleaseCheckPreflight(t *testing.T, env map[string]string) (int, string) {
	t.Helper()

	cmd := exec.Command("make", "-f", "../../Makefile", "release-check-preflight")
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}

	var exitErr *exec.ExitError
	if !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("release-check-preflight execution error: %v\noutput:\n%s", err, out)
	}
	if ok := errorAs(err, &exitErr); !ok {
		t.Fatalf("release-check-preflight returned non-exit error: %v\noutput:\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

func errorAs(err error, target interface{}) bool {
	switch v := target.(type) {
	case **exec.ExitError:
		exitErr, ok := err.(*exec.ExitError)
		if ok {
			*v = exitErr
			return true
		}
	}
	return false
}

func TestReleaseCheckPreflightRejectsSameOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check preflight path contracts are exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	shared := filepath.Join(tmp, "shared.out")

	exitCode, out := runReleaseCheckPreflight(t, map[string]string{
		"RELEASE_CHECK_BUILD_OUT": shared,
		"RELEASE_CHECK_SARIF_OUT": shared,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when outputs share a path\noutput:\n%s", out)
	}
	if !strings.Contains(out, "build and SARIF outputs must be different paths") {
		t.Fatalf("expected distinct-path rejection message, got:\n%s", out)
	}
}

func TestReleaseCheckPreflightRejectsExistingBuildOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check preflight path contracts are exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	buildOut := filepath.Join(tmp, "existing-build.out")
	sarifOut := filepath.Join(tmp, "inspect.sarif")
	if err := os.WriteFile(buildOut, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing build output: %v", err)
	}

	exitCode, out := runReleaseCheckPreflight(t, map[string]string{
		"RELEASE_CHECK_BUILD_OUT": buildOut,
		"RELEASE_CHECK_SARIF_OUT": sarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when build output already exists\noutput:\n%s", out)
	}
	if !strings.Contains(out, "build output already exists") {
		t.Fatalf("expected existing build output rejection message, got:\n%s", out)
	}
}

func TestReleaseCheckPreflightRejectsSymlinkPathComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink path-component check is exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	linkedDir := filepath.Join(tmp, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Fatalf("create symlink dir: %v", err)
	}

	exitCode, out := runReleaseCheckPreflight(t, map[string]string{
		"RELEASE_CHECK_BUILD_OUT": filepath.Join(linkedDir, "build.out"),
		"RELEASE_CHECK_SARIF_OUT": filepath.Join(tmp, "inspect.sarif"),
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when output path contains symlink component\noutput:\n%s", out)
	}
	if !strings.Contains(out, "contains symlink path component") {
		t.Fatalf("expected symlink-component rejection message, got:\n%s", out)
	}
}

func TestReleaseCheckPreflightAcceptsDistinctNonExistingPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release-check preflight path contracts are exercised on POSIX in CI")
	}

	tmp := t.TempDir()
	buildOut := filepath.Join(tmp, "ok-build.out")
	sarifOut := filepath.Join(tmp, "ok-inspect.sarif")

	exitCode, out := runReleaseCheckPreflight(t, map[string]string{
		"RELEASE_CHECK_BUILD_OUT": buildOut,
		"RELEASE_CHECK_SARIF_OUT": sarifOut,
	})
	if exitCode != 0 {
		t.Fatalf("expected zero exit for distinct non-existing outputs, got %d\noutput:\n%s", exitCode, out)
	}
}
