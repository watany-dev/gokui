package scan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanSkillRootLargeFile(t *testing.T) {
	root := t.TempDir()
	large := strings.Repeat("a", maxScanFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte(large), 0o644); err != nil {
		t.Fatalf("write large markdown: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	if findings[0].ID != "LARGE_TEXT_FILE" {
		t.Fatalf("finding ID = %q, want LARGE_TEXT_FILE", findings[0].ID)
	}
}

func TestScanSkillRootWalkError(t *testing.T) {
	_, err := ScanSkillRoot(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "failed walking skill files") {
		t.Fatalf("expected walk error, got %v", err)
	}
}

func TestScanSkillRootWalkPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission model differs on windows")
	}

	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	if err := os.WriteFile(filepath.Join(locked, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	_, err := ScanSkillRoot(locked)
	if err == nil || !strings.Contains(err.Error(), "failed walking skill files") {
		t.Fatalf("expected walk permission error, got %v", err)
	}
}

func TestScanSkillRootRejectsSymlinkSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.md")
	if err := os.WriteFile(target, []byte("# external"), 0o644); err != nil {
		t.Fatalf("write target file: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked.md")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := ScanSkillRoot(root)
	if err == nil || !strings.Contains(err.Error(), ruleScanSymlinkInSource) {
		t.Fatalf("expected symlink rule error, got %v", err)
	}
}

func TestScanSkillRootRejectsSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real-root")
	if err := os.Mkdir(realRoot, 0o755); err != nil {
		t.Fatalf("mkdir real root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRoot, "SKILL.md"), []byte("---\nname: s\ndescription: d\n---\n"), 0o644); err != nil {
		t.Fatalf("write skill: %v", err)
	}
	linkRoot := filepath.Join(parent, "root-link")
	if err := os.Symlink("real-root", linkRoot); err != nil {
		t.Fatalf("create root symlink: %v", err)
	}

	_, err := ScanSkillRoot(linkRoot)
	if err == nil || !strings.Contains(err.Error(), ruleScanSymlinkInSource) {
		t.Fatalf("expected symlink-root rejection, got %v", err)
	}
}

func TestScanSkillRootRejectsNonDirectoryRoot(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "not-a-dir.md")
	if err := os.WriteFile(rootFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write root file: %v", err)
	}

	_, err := ScanSkillRoot(rootFile)
	if err == nil || !strings.Contains(err.Error(), ruleScanSpecialFile) {
		t.Fatalf("expected non-directory root rejection, got %v", err)
	}
}

func TestScanSkillRootRejectsSpecialFileSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mkfifo is not available on windows")
	}

	root := t.TempDir()
	fifoPath := filepath.Join(root, "SKILL.md")
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo command not available")
	}
	if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
		t.Skipf("mkfifo unsupported in this environment: %v", err)
	}

	_, err := ScanSkillRoot(root)
	if err == nil || !strings.Contains(err.Error(), ruleScanSpecialFile) {
		t.Fatalf("expected special-file rule error, got %v", err)
	}
}

func TestScanSkillRootEnforcesMaxFileCount(t *testing.T) {
	origLimit := scanMaxFiles
	scanMaxFiles = 2
	t.Cleanup(func() { scanMaxFiles = origLimit })

	root := t.TempDir()
	for i := 0; i < 3; i++ {
		path := filepath.Join(root, fmt.Sprintf("doc-%d.md", i))
		if err := os.WriteFile(path, []byte("# test"), 0o644); err != nil {
			t.Fatalf("write markdown %d: %v", i, err)
		}
	}

	_, err := ScanSkillRoot(root)
	if err == nil || !strings.Contains(err.Error(), ruleScanFileCount) {
		t.Fatalf("expected max-file rule error, got %v", err)
	}
}

func TestScanSkillRootReadErrorPropagation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission behavior differs on windows")
	}

	root := t.TempDir()
	path := filepath.Join(root, "SKILL.md")
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(path, 0o644)

	_, err := ScanSkillRoot(root)
	if err == nil || !strings.Contains(err.Error(), "failed to read scan file") {
		t.Fatalf("expected scan read error, got %v", err)
	}
}

func TestScanTextFileErrorsAndDedup(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := scanTextFile(scanTarget{
			Absolute: filepath.Join(t.TempDir(), "missing.md"),
			Relative: "missing.md",
			Kind:     "markdown",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to read scan file") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("rejects non-regular file", func(t *testing.T) {
		dir := t.TempDir()
		_, err := scanTextFile(scanTarget{
			Absolute: dir,
			Relative: "dir-as-file",
			Kind:     "markdown",
		})
		if err == nil || !strings.Contains(err.Error(), ruleScanSpecialFile) {
			t.Fatalf("expected special-file error, got %v", err)
		}
	})

	t.Run("read failure", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}
		path := filepath.Join(t.TempDir(), "denied.md")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		defer os.Chmod(path, 0o644)

		_, err := scanTextFile(scanTarget{
			Absolute: path,
			Relative: "denied.md",
			Kind:     "markdown",
		})
		if err == nil || !strings.Contains(err.Error(), "failed to read scan file") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("rejects changed source identity", func(t *testing.T) {
		root := t.TempDir()
		originalPath := filepath.Join(root, "original.md")
		if err := os.WriteFile(originalPath, []byte("one"), 0o644); err != nil {
			t.Fatalf("write original file: %v", err)
		}
		otherPath := filepath.Join(root, "other.md")
		if err := os.WriteFile(otherPath, []byte("two"), 0o644); err != nil {
			t.Fatalf("write other file: %v", err)
		}
		originalInfo, err := os.Lstat(originalPath)
		if err != nil {
			t.Fatalf("lstat original file: %v", err)
		}

		_, err = scanTextFile(scanTarget{
			Absolute: otherPath,
			Relative: "other.md",
			Kind:     "markdown",
			Info:     originalInfo,
		})
		if err == nil || !strings.Contains(err.Error(), ruleScanSourceChanged) {
			t.Fatalf("expected changed-source error, got %v", err)
		}
	})

	t.Run("deduplicates findings", func(t *testing.T) {
		in := []Finding{
			{ID: "A", Severity: "high", File: "SKILL.md", Line: 10},
			{ID: "A", Severity: "high", File: "SKILL.md", Line: 10},
			{ID: "B", Severity: "critical", File: "SKILL.md", Line: 10},
		}
		out := deduplicateFindings(in)
		if len(out) != 2 {
			t.Fatalf("expected deduplicated findings length 2, got %d", len(out))
		}
	})
}
