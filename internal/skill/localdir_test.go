package skill

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeSkillDir(t *testing.T, dirName string, skillBody string) string {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, dirName)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir skill dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillBody), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	return dir
}

func TestValidateLocalDirInspectSource(t *testing.T) {
	t.Run("accepts matching directory and skill name", func(t *testing.T) {
		dir := writeSkillDir(t, "valid-skill", "---\nname: valid-skill\ndescription: Use when validating matching names.\n---\n")
		if err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit); err != nil {
			t.Fatalf("ValidateLocalDirInspectSource() error = %v", err)
		}
	})

	t.Run("missing source preserves sentinel", func(t *testing.T) {
		err := ValidateLocalDirInspectSource(filepath.Join(t.TempDir(), "missing-skill"), testFrontmatterLimit)
		if !errors.Is(err, ErrInspectSourceNotFound) {
			t.Fatalf("expected ErrInspectSourceNotFound, got %v", err)
		}
	})

	t.Run("rejects name mismatch with parent directory", func(t *testing.T) {
		dir := writeSkillDir(t, "different-dir", "---\nname: valid-skill\ndescription: Use when validating mismatch detection.\n---\n")
		err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), "frontmatter name must match directory name") {
			t.Fatalf("expected directory mismatch error, got %v", err)
		}
	})

	t.Run("rejects non-directory source", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		err := ValidateLocalDirInspectSource(path, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), "inspect local source must be a directory") {
			t.Fatalf("expected non-directory error, got %v", err)
		}
	})

	t.Run("rejects missing skill file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing-skill-file")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), "must contain SKILL.md at root") {
			t.Fatalf("expected missing SKILL.md error, got %v", err)
		}
	})

	t.Run("rejects invalid frontmatter", func(t *testing.T) {
		dir := writeSkillDir(t, "invalid-frontmatter", "# no frontmatter\n")
		err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), "must start with YAML frontmatter") {
			t.Fatalf("expected frontmatter error, got %v", err)
		}
	})

	t.Run("rejects special-file skill file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "special-skill")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		if err := os.Mkdir(filepath.Join(dir, "SKILL.md"), 0o755); err != nil {
			t.Fatalf("mkdir SKILL.md: %v", err)
		}
		err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), RuleFrontmatterSpecialFile) {
			t.Fatalf("expected special-file error, got %v", err)
		}
	})
}

func TestValidateLocalDirInspectSourceSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on windows")
	}

	t.Run("rejects source directory symlink", func(t *testing.T) {
		target := writeSkillDir(t, "target-skill", "---\nname: target-skill\ndescription: Use when testing source symlink rejection.\n---\n")
		link := filepath.Join(t.TempDir(), "skill-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink source: %v", err)
		}
		err := ValidateLocalDirInspectSource(link, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), RuleInspectSourceSymlink) {
			t.Fatalf("expected source symlink rejection, got %v", err)
		}
	})

	t.Run("rejects source path when ancestor directory is symlink", func(t *testing.T) {
		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "ancestor-skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, "SKILL.md"), []byte("---\nname: ancestor-skill\ndescription: Use when testing ancestor symlink source rejection.\n---\n"), 0o644); err != nil {
			t.Fatalf("write SKILL.md: %v", err)
		}
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("symlink parent: %v", err)
		}
		err := ValidateLocalDirInspectSource(filepath.Join(linkParent, "ancestor-skill"), testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), RuleInspectSourceSymlink) {
			t.Fatalf("expected ancestor symlink rejection, got %v", err)
		}
	})

	t.Run("rejects symlinked skill file", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "symlinked-skill")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("mkdir skill dir: %v", err)
		}
		target := filepath.Join(base, "real-skill.md")
		if err := os.WriteFile(target, []byte("---\nname: symlinked-skill\ndescription: Use when testing SKILL symlink rejection.\n---\n"), 0o644); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink("real-skill.md", filepath.Join(dir, "SKILL.md")); err != nil {
			t.Fatalf("symlink SKILL.md: %v", err)
		}
		err := ValidateLocalDirInspectSource(dir, testFrontmatterLimit)
		if err == nil || !strings.Contains(err.Error(), RuleFrontmatterSymlink) {
			t.Fatalf("expected SKILL symlink rejection, got %v", err)
		}
	})
}

func TestLocalDirPathGuardHelpers(t *testing.T) {
	t.Run("rejectSymlinkPath ignores missing tail", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing", "child")
		if err := rejectSymlinkPath(missing, "test path", "RULE_TEST"); err != nil {
			t.Fatalf("missing tail should be allowed for later stat handling, got %v", err)
		}
	})

	t.Run("rejectSymlinkPath reports lstat errors", func(t *testing.T) {
		err := rejectSymlinkPath("\x00", "test path", "RULE_TEST")
		if err == nil || !strings.Contains(err.Error(), "failed to evaluate test path") {
			t.Fatalf("expected lstat error, got %v", err)
		}
	})

	t.Run("symlinkCheckCandidates are root first", func(t *testing.T) {
		got := symlinkCheckCandidates(filepath.Join("a", "b", "c"))
		if len(got) < 3 || got[len(got)-1] != filepath.Clean(filepath.Join("a", "b", "c")) {
			t.Fatalf("unexpected candidates: %#v", got)
		}
	})

	t.Run("root-level path component classification", func(t *testing.T) {
		root := filepath.Clean(string(filepath.Separator))
		if isRootLevelPathComponent(root) {
			t.Fatalf("filesystem root should not be treated as root-level child: %q", root)
		}
		child := filepath.Join(root, "tmp")
		if !isRootLevelPathComponent(child) {
			t.Fatalf("direct child of filesystem root should be root-level component: %q", child)
		}
		if isRootLevelPathComponent(filepath.Join(child, "nested")) {
			t.Fatalf("nested absolute path should not be root-level component")
		}
		if isRootLevelPathComponent(filepath.Join("relative", "path")) {
			t.Fatalf("relative path should not be root-level component")
		}
	})
}
