package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseEvidenceScriptRejectsWithVulnAndBetaMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	cmd := exec.Command("bash", "../../scripts/collect-release-evidence.sh", "--with-vuln", "--beta")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for combined --with-vuln and --beta flags\noutput:\n%s", out)
	}

	text := string(out)
	if !strings.Contains(text, "--with-vuln cannot be combined with --beta") {
		t.Fatalf("expected mutually-exclusive-flag rejection message, got:\n%s", text)
	}
}

func TestReleaseEvidenceScriptSkipsGateWhenGitTreeIsDirty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script execution contract is exercised on POSIX in CI")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}

	// Force a deterministic dirty-tree signal for the clean-tree preflight.
	marker, err := os.CreateTemp(repoRoot, ".release-evidence-dirty-marker-*.tmp")
	if err != nil {
		t.Fatalf("create dirty marker file: %v", err)
	}
	markerPath := marker.Name()
	if closeErr := marker.Close(); closeErr != nil {
		t.Fatalf("close dirty marker file: %v", closeErr)
	}
	t.Cleanup(func() {
		_ = os.Remove(markerPath)
	})

	evidenceDir := filepath.Join(repoRoot, "releases", "evidence")
	before := map[string]struct{}{}
	if beforeEntries, readErr := os.ReadDir(evidenceDir); readErr == nil {
		before = make(map[string]struct{}, len(beforeEntries))
		for _, entry := range beforeEntries {
			before[entry.Name()] = struct{}{}
		}
	} else if !os.IsNotExist(readErr) {
		t.Fatalf("read evidence directory before script run: %v", readErr)
	}

	cmd := exec.Command("bash", "../../scripts/collect-release-evidence.sh", "--beta")
	customGoCache := filepath.Join(repoRoot, ".cache", "custom-go-build")
	customGoModCache := filepath.Join(repoRoot, ".cache", "custom-gomod")
	customGoPath := filepath.Join(repoRoot, ".cache", "custom-gopath")
	customXDGCacheHome := filepath.Join(repoRoot, ".cache", "custom-xdg")
	cmd.Env = append(
		os.Environ(),
		"GOCACHE="+customGoCache,
		"GOMODCACHE="+customGoModCache,
		"GOPATH="+customGoPath,
		"XDG_CACHE_HOME="+customXDGCacheHome,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for dirty-tree beta evidence run\noutput:\n%s", out)
	}

	afterEntries, err := os.ReadDir(evidenceDir)
	if err != nil {
		t.Fatalf("read evidence directory after script run: %v", err)
	}

	var created string
	for _, entry := range afterEntries {
		name := entry.Name()
		if _, ok := before[name]; ok {
			continue
		}
		if strings.HasSuffix(name, "-beta-audit.md") {
			created = name
			break
		}
	}
	if created == "" {
		t.Fatalf("expected beta evidence file creation on dirty-tree run\noutput:\n%s", out)
	}
	t.Cleanup(func() {
		_ = os.Remove(filepath.Join(evidenceDir, created))
	})

	evidencePath := filepath.Join(evidenceDir, created)
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read created evidence file: %v", err)
	}
	evidenceText := string(evidenceBytes)
	if !strings.Contains(evidenceText, "- git status clean: FAIL (exit=1)") {
		t.Fatalf("expected dirty-tree preflight failure in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "- beta-check: SKIPPED") {
		t.Fatalf("expected beta-check skipped marker in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "skipped because git status clean check failed") {
		t.Fatalf("expected explicit dirty-tree skip reason in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "- GOCACHE: "+customGoCache) {
		t.Fatalf("expected GOCACHE metadata line in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "- GOMODCACHE: "+customGoModCache) {
		t.Fatalf("expected GOMODCACHE metadata line in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "- GOPATH: "+customGoPath) {
		t.Fatalf("expected GOPATH metadata line in evidence file, got:\n%s", evidenceText)
	}
	if !strings.Contains(evidenceText, "- XDG_CACHE_HOME: "+customXDGCacheHome) {
		t.Fatalf("expected XDG_CACHE_HOME metadata line in evidence file, got:\n%s", evidenceText)
	}

	base := strings.TrimSuffix(created, ".md")
	skippedGateLogPath := filepath.Join(evidenceDir, "logs", base+"-beta-check.log")
	if _, statErr := os.Stat(skippedGateLogPath); statErr == nil {
		t.Fatalf("unexpected beta-check log for skipped dirty-tree run: %s", skippedGateLogPath)
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("stat skipped beta-check log: %v", statErr)
	}

	gitStatusLogPath := filepath.Join(evidenceDir, "logs", base+"-git-status.log")
	if _, statErr := os.Stat(gitStatusLogPath); statErr != nil {
		t.Fatalf("expected git-status log for dirty-tree run: %v", statErr)
	}
	t.Cleanup(func() {
		_ = os.Remove(gitStatusLogPath)
	})
}
