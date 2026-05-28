package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSkillRootFlagsNonUTF8InTextScanTargets(t *testing.T) {
	root := t.TempDir()
	invalidScript := append([]byte("echo safe\n"), 0xff)
	if err := os.WriteFile(filepath.Join(root, "run.sh"), invalidScript, 0o644); err != nil {
		t.Fatalf("write invalid utf-8 script: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "NON_UTF8_TEXT")
}

func TestScanSkillRootDoesNotFlagNonUTF8ForUnknownFiles(t *testing.T) {
	root := t.TempDir()
	invalidUnknown := append([]byte("prefix"), 0xff)
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), invalidUnknown, 0o644); err != nil {
		t.Fatalf("write invalid utf-8 unknown file: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "UNKNOWN_FILE_TYPE")
	for _, finding := range findings {
		if finding.ID == "NON_UTF8_TEXT" {
			t.Fatalf("unexpected NON_UTF8_TEXT finding for unknown file: %+v", finding)
		}
	}
}
