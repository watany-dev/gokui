package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeMatchingInstallReportForLockTest(t *testing.T, skillPath string, lock installLock) {
	t.Helper()

	report := installReport{
		SchemaVersion: reportSchemaVersion,
		Source: source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		},
		PolicyProfile:     lock.Policy.Profile,
		Decision:            "PASS",
		InstalledPath:       skillPath,
		Installed:           true,
		Findings:            nil,
		SeverityOverrides:   nil,
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal install report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, installReportFile), raw, 0o644); err != nil {
		t.Fatalf("write install report: %v", err)
	}
}
