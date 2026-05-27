package materialize

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
)

type archiveErrorStatter struct {
	err error
}

func (s archiveErrorStatter) Stat() (os.FileInfo, error) {
	return nil, s.err
}

func TestSafeJoinRejectsAbsoluteAndDot(t *testing.T) {
	root := t.TempDir()

	_, err := safeJoin(root, filepath.Join(string(filepath.Separator), "abs", "x"))
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected absolute-path error, got %v", err)
	}

	_, err = safeJoin(root, ".")
	if err == nil || !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("expected invalid-path error, got %v", err)
	}

	_, err = safeJoin(root, "C:/Windows/System32/drivers/etc/hosts")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected windows-drive absolute-path error, got %v", err)
	}

	_, err = safeJoin(root, "safe/../C:/Windows/System32/drivers/etc/hosts")
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected normalized windows-drive absolute-path error, got %v", err)
	}

	invalidName := string([]byte{'b', 0xff, 'a'})
	_, err = safeJoin(root, invalidName)
	if err == nil || !strings.Contains(err.Error(), ruleArchivePathInvalidUTF8) {
		t.Fatalf("expected invalid utf-8 archive path error, got %v", err)
	}
}

func TestSafeJoinPropertyNoEscapeNoPanic(t *testing.T) {
	root := t.TempDir()
	prop := func(name string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()

		joined, err := safeJoin(root, name)
		if err != nil {
			return true
		}
		rel, relErr := filepath.Rel(root, joined)
		if relErr != nil {
			return false
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatalf("safeJoin property failed: %v", err)
	}
}

func TestSafeJoinPropertyRejectsParentTraversal(t *testing.T) {
	root := t.TempDir()
	prop := func(depth uint8) bool {
		name := strings.Repeat("../", int(depth)+1) + "escape.txt"
		_, err := safeJoin(root, name)
		return err != nil
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("safeJoin traversal-rejection property failed: %v", err)
	}
}

func TestEnsureArchiveSourceStableFromOpen(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.zip")
	secondPath := filepath.Join(dir, "second.zip")
	if err := os.WriteFile(firstPath, []byte("first"), 0o644); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o644); err != nil {
		t.Fatalf("write second: %v", err)
	}

	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		t.Fatalf("lstat first: %v", err)
	}
	if err := ensureArchiveSourceStableFromOpen(firstInfo, archiveErrorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to open archive source") {
		t.Fatalf("expected archive source stat failure, got %v", err)
	}

	firstOpened, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open first: %v", err)
	}
	defer firstOpened.Close()
	if err := ensureArchiveSourceStableFromOpen(firstInfo, firstOpened, firstPath); err != nil {
		t.Fatalf("same archive source identity should pass, got %v", err)
	}

	secondOpened, err := os.Open(secondPath)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer secondOpened.Close()
	if err := ensureArchiveSourceStableFromOpen(firstInfo, secondOpened, secondPath); err == nil || !strings.Contains(err.Error(), ruleArchiveSourceChanged) {
		t.Fatalf("expected source-changed archive error, got %v", err)
	}
}

func TestRejectArchiveSourceSymlinkPathGuards(t *testing.T) {
	t.Run("allows missing path", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "missing.zip")
		if err := rejectArchiveSourceSymlinkPath(src); err != nil {
			t.Fatalf("missing path should not fail symlink guard, got %v", err)
		}
	})

	t.Run("allows ENOTDIR segment", func(t *testing.T) {
		base := t.TempDir()
		nonDir := filepath.Join(base, "not-dir")
		if err := os.WriteFile(nonDir, []byte("x"), 0o644); err != nil {
			t.Fatalf("write non-dir segment: %v", err)
		}
		src := filepath.Join(nonDir, "nested.zip")
		if err := rejectArchiveSourceSymlinkPath(src); err != nil {
			t.Fatalf("ENOTDIR path should not fail symlink guard, got %v", err)
		}
	})

	t.Run("invalid path reports evaluation failure", func(t *testing.T) {
		err := rejectArchiveSourceSymlinkPath("\x00")
		if err == nil || !strings.Contains(err.Error(), "failed to evaluate archive source path") {
			t.Fatalf("expected archive-source path evaluation failure, got %v", err)
		}
	})
}

func TestIsRootLevelPathComponent(t *testing.T) {
	if isRootLevelPathComponent("relative/path") {
		t.Fatal("relative path must not be treated as root-level component")
	}
	if isRootLevelPathComponent(string(os.PathSeparator)) {
		t.Fatal("filesystem root must not be treated as root-level component")
	}
	rootChild := rootChildPathForTest(t)
	if !isRootLevelPathComponent(rootChild) {
		t.Fatalf("expected root child to be treated as root-level component: %q", rootChild)
	}
	deeper := filepath.Join(rootChild, "tmp")
	if isRootLevelPathComponent(deeper) {
		t.Fatalf("deeper path must not be treated as root-level component: %q", deeper)
	}
}

func TestRejectArchiveSourceSymlinkPathAllowsRootLevelSymlinkComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("absolute root-level symlink layout differs on windows")
	}

	info, err := os.Lstat("/bin")
	if err != nil {
		t.Skipf("skip: lstat /bin failed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Skip("/bin is not a symlink on this environment")
	}

	src := filepath.Join("/bin", "gokui-root-level-symlink-guard-test.tar")
	if err := rejectArchiveSourceSymlinkPath(src); err != nil {
		t.Fatalf("expected root-level symlink component to be allowed, got %v", err)
	}
}

func rootChildPathForTest(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return filepath.Join(string(os.PathSeparator), "var")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("skip: getwd failed on windows: %v", err)
	}
	vol := filepath.VolumeName(cwd)
	if vol == "" {
		t.Skip("skip: windows volume name unavailable")
	}
	return filepath.Join(vol+string(os.PathSeparator), "var")
}
