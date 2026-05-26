package app

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInspectSARIFScriptRejectsOutputOutsideRepoRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := filepath.Join(t.TempDir(), "inspect-results.sarif")
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output outside repo root\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must resolve under repository root") {
		t.Fatalf("expected repository-root-only rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsOutputInsideGitDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	outPath := filepath.Join(repoRoot, ".git", "hooks", "inspect-results.sarif")
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output inside .git\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must resolve outside .git") {
		t.Fatalf("expected .git-path rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsDotDotPathSegments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "../inspect-results.sarif"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output with path traversal segment\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must not contain '..' path segments") {
		t.Fatalf("expected dot-dot segment rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsDirectoryLikeOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "inspect-results.sarif/"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif directory-like output path\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must be a non-directory file path") {
		t.Fatalf("expected directory-like path rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsDotDirectorySuffixOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "inspect-results.sarif/."
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif dot-directory-suffix output path\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must be a non-directory file path") {
		t.Fatalf("expected dot-directory-suffix rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsNonSarifOutputExtension(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "inspect-results.json"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for non-sarif output extension\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must end with .sarif") {
		t.Fatalf("expected non-sarif-extension rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsDotPathSegments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "reports/./inspect-results.sarif"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output with dot path segment\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must not contain '.' path segments") {
		t.Fatalf("expected dot-segment rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsEmptyPathSegments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "reports//inspect-results.sarif"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output with empty path segment\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must not contain empty path segments") {
		t.Fatalf("expected empty-segment rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsLeadingWhitespaceOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := " inspect-results.sarif"
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output with leading whitespace\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must not include leading or trailing whitespace") {
		t.Fatalf("expected leading-whitespace rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsTrailingWhitespaceOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	outPath := "inspect-results.sarif "
	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", outPath)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for inspect-sarif output with trailing whitespace\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must not include leading or trailing whitespace") {
		t.Fatalf("expected trailing-whitespace rejection message, got:\n%s", text)
	}
}

func TestInspectSARIFScriptRejectsControlCharactersInOutputPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	testCases := []struct {
		name    string
		outPath string
	}{
		{name: "tab in middle", outPath: "inspect\t-results.sarif"},
		{name: "del in middle", outPath: "inspect\x7f-results.sarif"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", tc.outPath)

			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected non-zero exit for inspect-sarif output with control characters %q\noutput:\n%s", tc.outPath, out)
			}
			text := string(out)
			if !strings.Contains(text, "must not contain ASCII control characters") {
				t.Fatalf("expected control-character rejection message, got:\n%s", text)
			}
		})
	}
}

func TestInspectSARIFScriptRejectsEmptyOutputPathArgument(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	cmd := exec.Command("bash", "../../scripts/generate-inspect-sarif.sh", "")

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for empty inspect-sarif output path argument\noutput:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "must be non-empty") {
		t.Fatalf("expected empty-path rejection message, got:\n%s", text)
	}
}
