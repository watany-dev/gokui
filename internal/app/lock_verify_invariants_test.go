package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
)

func TestLockRelativePathProperties(t *testing.T) {
	t.Run("windows drive prefixes are always invalid", func(t *testing.T) {
		prop := func(letter uint8, tail string) bool {
			drive := byte('A' + (letter % 26))
			path := fmt.Sprintf("%c:%s", drive, tail)
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("drive-prefix property failed: %v", err)
		}
	})

	t.Run("paths with backslash are always invalid", func(t *testing.T) {
		prop := func(a string, b string) bool {
			path := a + `\` + b
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("backslash property failed: %v", err)
		}
	})
}

func TestVerifyInstallReportDecisionAndFindingsInvariant(t *testing.T) {
	skillPath := t.TempDir()
	lock := installLock{
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
		Findings: lockFindingSummary{
			Critical: 0,
			High:     1,
			Medium:   0,
			Low:      0,
		},
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
		Findings: []inspectFinding{
			{ID: "UNPINNED_RUNTIME_TOOL", Severity: "high", File: "SKILL.md", Line: 1, Summary: "x"},
		},
	}

	writeReport := func(t *testing.T, in installReport) {
		t.Helper()
		raw, err := json.MarshalIndent(in, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	writeReport(t, report)
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected baseline install report check pass")
	}

	t.Run("decision must be pass", func(t *testing.T) {
		mutLock := lock
		mutLock.Policy.Decision = "rejected"

		mutReport := report
		mutReport.Decision = "REJECTED"
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "decision must be pass") {
			t.Fatalf("expected pass-only decision failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("findings summary mismatch", func(t *testing.T) {
		mutReport := report
		mutReport.Findings = nil
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "findings summary does not match lock findings") {
			t.Fatalf("expected findings mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
}
