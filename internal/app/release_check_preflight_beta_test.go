package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runBetaCheckPreflight(t *testing.T, env map[string]string) (int, string) {
	t.Helper()

	cmd := exec.Command("make", "-f", "../../Makefile", "beta-check-preflight")
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
		t.Fatalf("beta-check-preflight execution error: %v\noutput:\n%s", err, out)
	}
	if ok := errors.As(err, &exitErr); !ok {
		t.Fatalf("beta-check-preflight returned non-exit error: %v\noutput:\n%s", err, out)
	}
	return exitErr.ExitCode(), string(out)
}

func TestBetaCheckPreflightRejectsSameOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	shared := releaseCheckRepoLocalPath(t, "beta-shared.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    shared,
		"BETA_CHECK_SARIF_OUT":    shared,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when beta outputs share a path\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_OUTPUT_PATH_CONFLICT]") {
		t.Fatalf("expected distinct-path rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "build and SARIF outputs must be different paths") {
		t.Fatalf("expected distinct-path rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsSameOutputPathAfterNormalization(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	root := releaseCheckRepoRootPath(t)
	safeName := strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	baseDir := filepath.Join(root, ".cache", "release-check-preflight-tests")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatalf("mkdir preflight test base dir: %v", err)
	}
	tempDir, err := os.MkdirTemp(baseDir, safeName+"-")
	if err != nil {
		t.Fatalf("create preflight test temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	betaBuildOut := filepath.Join(tempDir, "nested", "..", "shared.sarif")
	betaSarifOut := filepath.Join(tempDir, "shared.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when normalized beta outputs share a path\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_OUTPUT_PATH_CONFLICT]") {
		t.Fatalf("expected normalized distinct-path rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "build and SARIF outputs must be different paths") {
		t.Fatalf("expected normalized distinct-path rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightAllowsExistingOutputs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	buildOut := releaseCheckRepoLocalPath(t, "existing-beta-build.out")
	sarifOut := releaseCheckRepoLocalPath(t, "existing-beta-inspect.sarif")
	if err := os.MkdirAll(filepath.Dir(buildOut), 0o755); err != nil {
		t.Fatalf("mkdir beta build output parent: %v", err)
	}
	if err := os.WriteFile(buildOut, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing beta build output: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(sarifOut), 0o755); err != nil {
		t.Fatalf("mkdir beta SARIF output parent: %v", err)
	}
	if err := os.WriteFile(sarifOut, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing beta SARIF output: %v", err)
	}

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT": buildOut,
		"BETA_CHECK_SARIF_OUT": sarifOut,
	})
	if exitCode != 0 {
		t.Fatalf("expected zero exit when beta outputs already exist\noutput:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsInvalidSARIFExtensionFromBetaOutputVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaBuildOut := releaseCheckRepoLocalPath(t, "beta-build.out")
	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.txt")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for beta SARIF output without .sarif extension\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_SARIF_OUT_INVALID]") {
		t.Fatalf("expected invalid SARIF output rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "SARIF output path must end with .sarif") {
		t.Fatalf("expected invalid SARIF output rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsRootOrDirectoryLikeSARIFOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	testCases := []struct {
		name     string
		sarifOut string
	}{
		{name: "dot path", sarifOut: "."},
		{name: "root path", sarifOut: "/"},
		{name: "directory-like trailing slash", sarifOut: filepath.Join(t.TempDir(), "dir-like") + "/"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, out := runBetaCheckPreflight(t, map[string]string{
				"BETA_CHECK_BUILD_OUT":    releaseCheckRepoLocalPath(t, "beta-build.out"),
				"BETA_CHECK_SARIF_OUT":    tc.sarifOut,
				"RELEASE_CHECK_BUILD_OUT": releaseCheckRepoLocalPath(t, "release-build.out"),
				"RELEASE_CHECK_SARIF_OUT": releaseCheckRepoLocalPath(t, "release-inspect.sarif"),
			})
			if exitCode == 0 {
				t.Fatalf("expected non-zero exit for invalid beta SARIF output path %q\noutput:\n%s", tc.sarifOut, out)
			}
			if !strings.Contains(out, "[RC_PREFLIGHT_SARIF_OUT_INVALID]") {
				t.Fatalf("expected non-root beta SARIF output rejection code, got:\n%s", out)
			}
			if !strings.Contains(out, "SARIF output path must be a non-root file path") {
				t.Fatalf("expected non-root beta SARIF output rejection message, got:\n%s", out)
			}
		})
	}
}

func TestBetaCheckPreflightRejectsGitPathFromBetaOutputVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	root := releaseCheckRepoRootPath(t)
	betaBuildOut := filepath.Join(root, ".git", "beta-build.out")
	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for beta build output under .git\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_BUILD_OUT_INVALID]") {
		t.Fatalf("expected invalid build output rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "build output path must be a non-root file path outside .git") {
		t.Fatalf("expected .git build output rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightIgnoresInvalidReleaseCheckOutputEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaBuildOut := releaseCheckRepoLocalPath(t, "beta-build.out")
	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": ".",
		"RELEASE_CHECK_SARIF_OUT": "/",
	})
	if exitCode != 0 {
		t.Fatalf("expected zero exit when only RELEASE_CHECK_* env values are invalid\noutput:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsSymlinkedBuildOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	basePath := releaseCheckRepoLocalPath(t, "seed")
	baseDir := filepath.Dir(basePath)
	realDir := filepath.Join(baseDir, "real")
	linkDir := filepath.Join(baseDir, "symlinked")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real output dir: %v", err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("create symlink output dir: %v", err)
	}

	betaBuildOut := filepath.Join(linkDir, "beta-build.out")
	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for symlinked beta build output path\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_BUILD_OUT_SYMLINK]") {
		t.Fatalf("expected symlink build output rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "build output path contains symlink path component") {
		t.Fatalf("expected symlink build output rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsSymlinkedSARIFOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	basePath := releaseCheckRepoLocalPath(t, "seed")
	baseDir := filepath.Dir(basePath)
	realDir := filepath.Join(baseDir, "real")
	linkDir := filepath.Join(baseDir, "symlinked")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real output dir: %v", err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("create symlink output dir: %v", err)
	}

	betaBuildOut := releaseCheckRepoLocalPath(t, "beta-build.out")
	betaSarifOut := filepath.Join(linkDir, "beta-inspect.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for symlinked beta SARIF output path\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_SARIF_OUT_SYMLINK]") {
		t.Fatalf("expected symlink SARIF output rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "SARIF output path contains symlink path component") {
		t.Fatalf("expected symlink SARIF output rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsBuildOutputEmptyPathSegmentsFromBetaVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaBuildOut := ".cache//beta-build.out"
	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for beta build output with empty path segment\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_BUILD_OUT_INVALID]") {
		t.Fatalf("expected build output empty-segment rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "build output path must not contain empty path segments") {
		t.Fatalf("expected build output empty-segment rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsBuildOutputDotSegmentsFromBetaVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaSarifOut := releaseCheckRepoLocalPath(t, "beta-inspect.sarif")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	testCases := []struct {
		name         string
		betaBuildOut string
	}{
		{name: "dot segment in middle", betaBuildOut: ".cache/./beta-build.out"},
		{name: "dotdot segment in middle", betaBuildOut: ".cache/tmp/../beta-build.out"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, out := runBetaCheckPreflight(t, map[string]string{
				"BETA_CHECK_BUILD_OUT":    tc.betaBuildOut,
				"BETA_CHECK_SARIF_OUT":    betaSarifOut,
				"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
				"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
			})
			if exitCode == 0 {
				t.Fatalf("expected non-zero exit for beta build output path with dot/dotdot segment %q\noutput:\n%s", tc.betaBuildOut, out)
			}
			if !strings.Contains(out, "[RC_PREFLIGHT_BUILD_OUT_INVALID]") {
				t.Fatalf("expected build output dot/dotdot-segment rejection code, got:\n%s", out)
			}
			if !strings.Contains(out, "build output path must not contain '.' or '..' path segments") {
				t.Fatalf("expected build output dot/dotdot-segment rejection message, got:\n%s", out)
			}
		})
	}
}

func TestBetaCheckPreflightRejectsSARIFOutputEmptyPathSegmentsFromBetaVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaBuildOut := releaseCheckRepoLocalPath(t, "beta-build.out")
	betaSarifOut := ".cache//beta-inspect.sarif"
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	exitCode, out := runBetaCheckPreflight(t, map[string]string{
		"BETA_CHECK_BUILD_OUT":    betaBuildOut,
		"BETA_CHECK_SARIF_OUT":    betaSarifOut,
		"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
		"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
	})
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit for beta SARIF output with empty path segment\noutput:\n%s", out)
	}
	if !strings.Contains(out, "[RC_PREFLIGHT_SARIF_OUT_INVALID]") {
		t.Fatalf("expected SARIF output empty-segment rejection code, got:\n%s", out)
	}
	if !strings.Contains(out, "SARIF output path must not contain empty path segments") {
		t.Fatalf("expected SARIF output empty-segment rejection message, got:\n%s", out)
	}
}

func TestBetaCheckPreflightRejectsSARIFOutputDotSegmentsFromBetaVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preflight path contracts are exercised on POSIX in CI")
	}

	betaBuildOut := releaseCheckRepoLocalPath(t, "beta-build.out")
	releaseBuildOut := releaseCheckRepoLocalPath(t, "release-build.out")
	releaseSarifOut := releaseCheckRepoLocalPath(t, "release-inspect.sarif")

	testCases := []struct {
		name         string
		betaSarifOut string
	}{
		{name: "dot segment in middle", betaSarifOut: ".cache/./beta-inspect.sarif"},
		{name: "dotdot segment in middle", betaSarifOut: ".cache/tmp/../beta-inspect.sarif"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, out := runBetaCheckPreflight(t, map[string]string{
				"BETA_CHECK_BUILD_OUT":    betaBuildOut,
				"BETA_CHECK_SARIF_OUT":    tc.betaSarifOut,
				"RELEASE_CHECK_BUILD_OUT": releaseBuildOut,
				"RELEASE_CHECK_SARIF_OUT": releaseSarifOut,
			})
			if exitCode == 0 {
				t.Fatalf("expected non-zero exit for beta SARIF output path with dot/dotdot segment %q\noutput:\n%s", tc.betaSarifOut, out)
			}
			if !strings.Contains(out, "[RC_PREFLIGHT_SARIF_OUT_INVALID]") {
				t.Fatalf("expected SARIF output dot/dotdot-segment rejection code, got:\n%s", out)
			}
			if !strings.Contains(out, "SARIF output path must not contain '.' or '..' path segments") {
				t.Fatalf("expected SARIF output dot/dotdot-segment rejection message, got:\n%s", out)
			}
		})
	}
}

func TestBetaCheckPreflightCanRunConsecutively(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("beta-check preflight contract is exercised on POSIX in CI")
	}

	buildOut := releaseCheckRepoLocalPath(t, "beta-consecutive-build.out")
	sarifOut := releaseCheckRepoLocalPath(t, "beta-consecutive-inspect.sarif")
	preflightEnv := map[string]string{
		"BETA_CHECK_BUILD_OUT": buildOut,
		"BETA_CHECK_SARIF_OUT": sarifOut,
	}

	for i := 1; i <= 2; i++ {
		exitCode, out := runBetaCheckPreflight(t, preflightEnv)
		if exitCode != 0 {
			t.Fatalf("beta-check-preflight run %d should succeed\noutput:\n%s", i, out)
		}
	}
}
