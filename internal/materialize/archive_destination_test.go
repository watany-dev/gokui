package materialize

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtractArchiveRejectsNonEmptyDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.zip")
	createZip(t, src, map[string]string{
		"SKILL.md": "---\nname: x\ndescription: d\n---\n",
	})

	dest := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "exists.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	err := ExtractArchive(src, "zip", dest, Limits{})
	if err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("expected non-empty destination error, got %v", err)
	}
}

func TestExtractArchiveRejectsMissingOrFileDestination(t *testing.T) {
	src := filepath.Join(t.TempDir(), "skill.zip")
	createZip(t, src, map[string]string{
		"SKILL.md": "---\nname: x\ndescription: d\n---\n",
	})

	t.Run("missing destination", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "missing")
		err := ExtractArchive(src, "zip", dest, Limits{})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing destination error, got %v", err)
		}
	})

	t.Run("destination is file", func(t *testing.T) {
		destFile := filepath.Join(t.TempDir(), "dest-file")
		if err := os.WriteFile(destFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write dest file: %v", err)
		}
		err := ExtractArchive(src, "zip", destFile, Limits{})
		if err == nil || !strings.Contains(err.Error(), "must be a directory") {
			t.Fatalf("expected file-destination error, got %v", err)
		}
	})
}

func TestEnsureEmptyDirReadFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission model differs on windows")
	}

	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	err := ensureEmptyDir(locked)
	if err == nil || !strings.Contains(err.Error(), "failed to read destination directory") {
		t.Fatalf("expected readdir error, got %v", err)
	}
}

func TestDetectSkillRootRejectsAmbiguousLayout(t *testing.T) {
	t.Run("multiple top-level directories", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
			t.Fatalf("mkdir a: %v", err)
		}
		if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
			t.Fatalf("mkdir b: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected ambiguous layout error, got %v", err)
		}
	})

	t.Run("single top-level directory with extra top-level file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "skill"), 0o755); err != nil {
			t.Fatalf("mkdir skill: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "skill", "SKILL.md"), []byte("---\nname: skill\ndescription: d\n---\n"), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("extra"), 0o644); err != nil {
			t.Fatalf("write README.md: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected extra-top-level-file rejection, got %v", err)
		}
	})
}

func TestDetectSkillRootErrorCases(t *testing.T) {
	t.Run("missing extracted directory", func(t *testing.T) {
		_, err := DetectSkillRoot(filepath.Join(t.TempDir(), "missing"))
		if err == nil || !strings.Contains(err.Error(), "failed to read extracted archive") {
			t.Fatalf("expected read-dir error, got %v", err)
		}
	})

	t.Run("single top-level directory without SKILL", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "one"), 0o755); err != nil {
			t.Fatalf("mkdir one: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "one", "README.md"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write readme: %v", err)
		}

		_, err := DetectSkillRoot(dir)
		if err == nil || !strings.Contains(err.Error(), "single top-level directory") {
			t.Fatalf("expected missing-skill error, got %v", err)
		}
	})
}
