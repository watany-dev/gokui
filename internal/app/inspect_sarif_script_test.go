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
