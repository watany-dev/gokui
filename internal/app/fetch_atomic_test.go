package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestFetchSkillAtomic(t *testing.T) {
	sourceDir := createSkillSourceForInstallTest(t, "atomic-fetch-skill")
	outRoot := filepath.Join(t.TempDir(), "q")
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		t.Fatalf("mkdir out root: %v", err)
	}

	dest, err := fetchSkillAtomic(sourceDir, outRoot, "atomic-fetch-skill")
	if err != nil {
		t.Fatalf("fetchSkillAtomic() error = %v", err)
	}
	if dest != filepath.Join(outRoot, "atomic-fetch-skill") {
		t.Fatalf("dest = %q", dest)
	}

	if _, err := os.Stat(filepath.Join(dest, "SKILL.md")); err != nil {
		t.Fatalf("expected SKILL.md after fetch copy: %v", err)
	}

	t.Run("fails for bad output root and stat errors", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "fetch-atomic-fail")
		targetFile := filepath.Join(t.TempDir(), "target-file")
		if err := os.WriteFile(targetFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write target file: %v", err)
		}
		_, err := fetchSkillAtomic(sourceDir, targetFile, "fetch-atomic-fail")
		if err == nil || !strings.Contains(err.Error(), "failed to check fetch output target") {
			t.Fatalf("expected check-target error, got %v", err)
		}

		missingRoot := filepath.Join(t.TempDir(), "missing", "q")
		_, err = fetchSkillAtomic(sourceDir, missingRoot, "fetch-atomic-fail")
		if err == nil || !strings.Contains(err.Error(), "failed to create fetch staging directory") {
			t.Fatalf("expected staging error, got %v", err)
		}

		_, err = fetchSkillAtomic(filepath.Join(t.TempDir(), "missing-source"), outRoot, "fetch-atomic-fail")
		if err == nil {
			t.Fatal("expected copy error for missing source")
		}

		_, err = fetchSkillAtomic(sourceDir, outRoot, "nested/path")
		if err == nil || !strings.Contains(err.Error(), "failed to finalize fetch") {
			t.Fatalf("expected rename error for nested path, got %v", err)
		}

		if runtime.GOOS != "windows" {
			symlinkOut := filepath.Join(t.TempDir(), "out")
			if err := os.Mkdir(symlinkOut, 0o755); err != nil {
				t.Fatalf("mkdir symlink out: %v", err)
			}
			realExisting := filepath.Join(t.TempDir(), "real-existing")
			if err := os.Mkdir(realExisting, 0o755); err != nil {
				t.Fatalf("mkdir real existing: %v", err)
			}
			if err := os.Symlink(realExisting, filepath.Join(symlinkOut, "fetch-atomic-fail")); err != nil {
				t.Fatalf("create output entry symlink: %v", err)
			}
			_, err = fetchSkillAtomic(sourceDir, symlinkOut, "fetch-atomic-fail")
			if err == nil || !strings.Contains(err.Error(), rulepkg.FetchOutputEntrySymlink.ID) {
				t.Fatalf("expected output-entry symlink rejection, got %v", err)
			}
		}
	})
}
