package app

import (
	"os"
	"path/filepath"
	"testing"
)

func createSkillSourceForInstallTest(t *testing.T, name string) string {
	t.Helper()
	root := t.TempDir()
	skillDir := filepath.Join(root, name)
	if err := os.Mkdir(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir skill dir: %v", err)
	}
	content := "---\nname: " + name + "\ndescription: Use when testing install atomic path.\n---\n\n# Skill\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "README.md"), []byte("fixture"), 0o644); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	return skillDir
}
