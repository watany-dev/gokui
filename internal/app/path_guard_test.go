package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
)

func TestRejectSymlinkPath(t *testing.T) {
	t.Run("allows missing path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing")
		if err := rejectSymlinkPath(missing, "test path", "RULE_TEST"); err != nil {
			t.Fatalf("expected missing path to be allowed, got %v", err)
		}
	})

	t.Run("allows regular directory path", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "regular")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := rejectSymlinkPath(dir, "test path", "RULE_TEST"); err != nil {
			t.Fatalf("expected regular dir to be allowed, got %v", err)
		}
	})

	t.Run("allows ENOTDIR path for downstream mkdir handling", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		child := filepath.Join(file, "child")
		if err := rejectSymlinkPath(child, "test path", "RULE_TEST"); err != nil {
			t.Fatalf("expected ENOTDIR path to be allowed, got %v", err)
		}
	})

	t.Run("rejects symlink path", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		target := filepath.Join(base, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("mkdir target: %v", err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink("target", link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		err := rejectSymlinkPath(link, "test path", "RULE_TEST")
		if err == nil || !strings.Contains(err.Error(), "RULE_TEST") {
			t.Fatalf("expected symlink rejection rule id, got %v", err)
		}
	})

	t.Run("rejects path when ancestor directory is a symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		real := filepath.Join(base, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatalf("mkdir real: %v", err)
		}
		realChild := filepath.Join(real, "child")
		if err := os.Mkdir(realChild, 0o755); err != nil {
			t.Fatalf("mkdir real child: %v", err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink("real", link); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		err := rejectSymlinkPath(filepath.Join(link, "child"), "test path", "RULE_TEST")
		if err == nil || !strings.Contains(err.Error(), "RULE_TEST") {
			t.Fatalf("expected ancestor symlink rejection rule id, got %v", err)
		}
	})

	t.Run("returns evaluation error for invalid path", func(t *testing.T) {
		err := rejectSymlinkPath("\x00", "test path", "RULE_TEST")
		if err == nil || !strings.Contains(err.Error(), "failed to evaluate") {
			t.Fatalf("expected evaluate error, got %v", err)
		}
	})
}

func TestRejectSymlinkPathPropertyNoPanic(t *testing.T) {
	base := t.TempDir()
	prop := func(raw string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		_ = rejectSymlinkPath(filepath.Join(base, raw), "property path", "RULE_PROPERTY")
		return true
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("rejectSymlinkPath panic-safety property failed: %v", err)
	}
}

func TestIsRootLevelPathComponent(t *testing.T) {
	if isRootLevelPathComponent("relative/path") {
		t.Fatal("relative path must not be treated as root-level component")
	}
	if isRootLevelPathComponent(string(os.PathSeparator)) {
		t.Fatal("filesystem root must not be treated as root-level component")
	}
	rootChild := filepath.Join(string(os.PathSeparator), "var")
	if !isRootLevelPathComponent(rootChild) {
		t.Fatalf("expected root child to be treated as root-level component: %q", rootChild)
	}
	deeper := filepath.Join(rootChild, "tmp")
	if isRootLevelPathComponent(deeper) {
		t.Fatalf("deeper path must not be treated as root-level component: %q", deeper)
	}
}
