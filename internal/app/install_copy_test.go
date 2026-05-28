package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestCopyTreeNormalizedRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "regular.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if err := os.Symlink("regular.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	dst := t.TempDir()
	err := copyTreeNormalized(src, filepath.Join(dst, "copy"))
	if err == nil || !strings.Contains(err.Error(), "contains symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestCopyTreeNormalizedRejectsSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real-root")
	if err := os.Mkdir(realRoot, 0o755); err != nil {
		t.Fatalf("mkdir real root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realRoot, "regular.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	linkRoot := filepath.Join(parent, "root-link")
	if err := os.Symlink("real-root", linkRoot); err != nil {
		t.Fatalf("create root symlink: %v", err)
	}

	dst := t.TempDir()
	err := copyTreeNormalized(linkRoot, filepath.Join(dst, "copy"))
	if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceSymlink.ID) {
		t.Fatalf("expected symlink-root rejection, got %v", err)
	}
}

func TestCopyTreeNormalizedRejectsNonDirectoryRoot(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(rootFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write root file: %v", err)
	}

	dst := t.TempDir()
	err := copyTreeNormalized(rootFile, filepath.Join(dst, "copy"))
	if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceSpecialFile.ID) {
		t.Fatalf("expected non-directory-root rejection, got %v", err)
	}
}

func TestCopyTreeNormalizedRejectsSpecialFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fifo behavior differs on windows")
	}

	src := t.TempDir()
	fifo := filepath.Join(src, "pipe.fifo")
	if err := mkfifoForTest(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	dst := t.TempDir()
	err := copyTreeNormalized(src, filepath.Join(dst, "copy"))
	if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceSpecialFile.ID) {
		t.Fatalf("expected special-file rejection, got %v", err)
	}
}

func TestCopyTreeNormalizedLimitGuards(t *testing.T) {
	t.Run("enforces max file count", func(t *testing.T) {
		origLimit := installMaxCopyFiles
		installMaxCopyFiles = 1
		t.Cleanup(func() { installMaxCopyFiles = origLimit })

		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		if err := os.WriteFile(filepath.Join(src, "b.txt"), []byte("b"), 0o644); err != nil {
			t.Fatalf("write b.txt: %v", err)
		}
		err := copyTreeNormalized(src, filepath.Join(t.TempDir(), "dst"))
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceFileCountExceeded.ID) {
			t.Fatalf("expected max-file-count copy error, got %v", err)
		}
	})

	t.Run("enforces max total bytes", func(t *testing.T) {
		origLimit := installMaxCopyTotalBytes
		installMaxCopyTotalBytes = 1
		t.Cleanup(func() { installMaxCopyTotalBytes = origLimit })

		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("ab"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		err := copyTreeNormalized(src, filepath.Join(t.TempDir(), "dst"))
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceTotalBytesExceeded.ID) {
			t.Fatalf("expected max-total-bytes copy error, got %v", err)
		}
	})

	t.Run("enforces zero total bytes budget", func(t *testing.T) {
		origLimit := installMaxCopyTotalBytes
		installMaxCopyTotalBytes = 0
		t.Cleanup(func() { installMaxCopyTotalBytes = origLimit })

		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		err := copyTreeNormalized(src, filepath.Join(t.TempDir(), "dst"))
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceTotalBytesExceeded.ID) {
			t.Fatalf("expected zero-budget copy error, got %v", err)
		}
	})

	t.Run("enforces max file bytes", func(t *testing.T) {
		origLimit := installMaxCopyFileBytes
		installMaxCopyFileBytes = 1
		t.Cleanup(func() { installMaxCopyFileBytes = origLimit })

		src := t.TempDir()
		if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("ab"), 0o644); err != nil {
			t.Fatalf("write a.txt: %v", err)
		}
		err := copyTreeNormalized(src, filepath.Join(t.TempDir(), "dst"))
		if err == nil || !strings.Contains(err.Error(), rulepkg.InstallSourceFileTooLarge.ID) {
			t.Fatalf("expected max-file-bytes copy error, got %v", err)
		}
	})
}
