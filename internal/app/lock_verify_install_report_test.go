package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestVerifyInstallReportFailures(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "report-failure-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	seedReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "report-failure-skill", seedReport)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock() error = %v", err)
	}

	t.Run("missing report", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		originalReport, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read original report: %v", err)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report: %v", err)
		}
		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "failed to read install report") {
			t.Fatalf("expected missing report failure, got ok=%v detail=%q", ok, detail)
		}
		if err := os.WriteFile(reportPath, originalReport, 0o644); err != nil {
			t.Fatalf("restore report: %v", err)
		}
	})

	t.Run("source mismatch", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		var rep installReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		rep.Source.Input = "github:org/repo//skills/report-failure-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		updated, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(reportPath, updated, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}

		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "source does not match lock source") {
			t.Fatalf("expected source mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
}

func TestVerifyInstallReportValidationBranches(t *testing.T) {
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
	}

	writeReport := func(t *testing.T, payload string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), []byte(payload), 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	t.Run("invalid json", func(t *testing.T) {
		writeReport(t, "{")
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "invalid install report JSON") {
			t.Fatalf("expected invalid json failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("invalid utf-8 payload", func(t *testing.T) {
		invalidUTF8Report := append([]byte(`{"schema_version":"0.1.0-draft","source":{"input":"/tmp/src","kind":"local-dir"},"policy_profile":"strict","decision":"PASS","note":"`), 0xff)
		invalidUTF8Report = append(invalidUTF8Report, []byte(`"}`)...)
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), invalidUTF8Report, 0o644); err != nil {
			t.Fatalf("write invalid utf-8 report: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, rulepkg.InstallReportInvalidUTF8.ID) {
			t.Fatalf("expected invalid utf-8 report failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("oversized report", func(t *testing.T) {
		writeReport(t, `{"schema_version":"0.1.0-draft"}`)
		ok, detail := verifyInstallReportWithLimit(skillPath, lock, 8)
		if ok || !strings.Contains(detail, rulepkg.InstallReportTooLarge.ID) {
			t.Fatalf("expected oversized report failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("report path is directory", func(t *testing.T) {
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		if err := os.Mkdir(reportPath, 0o755); err != nil {
			t.Fatalf("mkdir report path: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, rulepkg.InstallReportSpecialFile.ID) {
			t.Fatalf("expected special-file failure for directory report path, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report directory: %v", err)
		}
	})

	t.Run("report path is symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		target := filepath.Join(skillPath, "real-report.json")
		if err := os.WriteFile(target, []byte(`{"schema_version":"0.1.0-draft"}`), 0o644); err != nil {
			t.Fatalf("write real report: %v", err)
		}
		if err := os.Symlink("real-report.json", reportPath); err != nil {
			t.Fatalf("create report symlink: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, rulepkg.InstallReportSymlink.ID) {
			t.Fatalf("expected report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report symlink: %v", err)
		}
	})

	t.Run("report path under ancestor symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill: %v", err)
		}
		valid := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "/tmp/src",
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			InstalledPath: filepath.Join(base, "link-parent", "skill"),
			Installed:     true,
		}
		raw, err := json.MarshalIndent(valid, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}

		ok, detail := verifyInstallReport(filepath.Join(linkParent, "skill"), lock)
		if ok || !strings.Contains(detail, rulepkg.InstallReportSymlink.ID) {
			t.Fatalf("expected ancestor report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
	})

	valid := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
	}
	raw, err := json.MarshalIndent(valid, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid report: %v", err)
	}
	writeReport(t, string(raw))
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected valid report check pass")
	}

	cases := []struct {
		name      string
		mutate    func(*installReport)
		detailHas string
	}{
		{
			name: "empty schema",
			mutate: func(r *installReport) {
				r.SchemaVersion = ""
			},
			detailHas: "schema_version is empty",
		},
		{
			name: "unsupported schema",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.0.0-test"
			},
			detailHas: "schema_version is unsupported",
		},
		{
			name: "schema has C0/C1 control character",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.1.0-draft\u008f"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u00850.1.0-draft"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u0085"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u0000"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character only",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u007f"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character at edge",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u007f0.1.0-draft"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has surrounding whitespace",
			mutate: func(r *installReport) {
				r.SchemaVersion = " 0.1.0-draft "
			},
			detailHas: "schema_version must not contain leading or trailing whitespace",
		},
		{
			name: "schema has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.1.0-draft\u200d"
			},
			detailHas: "schema_version must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty source input",
			mutate: func(r *installReport) {
				r.Source.Input = ""
			},
			detailHas: "source input is empty",
		},
		{
			name: "source input has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Source.Input = " " + r.Source.Input + " "
			},
			detailHas: "source input must not contain leading or trailing whitespace",
		},
		{
			name: "source input has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Source.Input = "/tmp/\u008fsrc"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Source.Input = "\u0085/tmp/src"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Source.Input = "\u0085"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.Source.Input = "\u0000"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has DEL control character only",
			mutate: func(r *installReport) {
				r.Source.Input = "\u007f"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has DEL control character at edge",
			mutate: func(r *installReport) {
				r.Source.Input = "\u007f/tmp/src"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Source.Input = "/tmp/src\u200d"
			},
			detailHas: "source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty source kind",
			mutate: func(r *installReport) {
				r.Source.Kind = ""
			},
			detailHas: "source kind is empty",
		},
		{
			name: "source kind has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Source.Kind = " " + r.Source.Kind + " "
			},
			detailHas: "source kind must not contain leading or trailing whitespace",
		},
		{
			name: "source kind has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Source.Kind = "local-\u008fdir"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u0085local-dir"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u0085"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u0000"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has DEL control character only",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u007f"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has DEL control character at edge",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u007flocal-dir"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Source.Kind = "local-dir\u200d"
			},
			detailHas: "source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty profile",
			mutate: func(r *installReport) {
				r.PolicyProfile = ""
			},
			detailHas: "policy profile is empty",
		},
		{
			name: "profile mismatch",
			mutate: func(r *installReport) {
				r.PolicyProfile = "team"
			},
			detailHas: "policy profile does not match",
		},
		{
			name: "profile has surrounding whitespace",
			mutate: func(r *installReport) {
				r.PolicyProfile = " strict "
			},
			detailHas: "policy profile must not contain leading or trailing whitespace",
		},
		{
			name: "profile has C0/C1 control character",
			mutate: func(r *installReport) {
				r.PolicyProfile = "stric\u008ft"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u0085strict"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u0085"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u0000"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has DEL control character only",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u007f"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has DEL control character at edge",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u007fstrict"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.PolicyProfile = "strict\u200d"
			},
			detailHas: "policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "profile not canonical lowercase",
			mutate: func(r *installReport) {
				r.PolicyProfile = "Strict"
			},
			detailHas: "policy profile must be canonical lowercase without surrounding whitespace",
		},
		{
			name: "decision mismatch",
			mutate: func(r *installReport) {
				r.Decision = "REJECTED"
			},
			detailHas: "decision does not match",
		},
		{
			name: "decision has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Decision = " PASS "
			},
			detailHas: "decision must not contain leading or trailing whitespace",
		},
		{
			name: "decision has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Decision = "PAS\u008fS"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Decision = "\u0085PASS"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Decision = "\u0085"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.Decision = "\u0000"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has DEL control character only",
			mutate: func(r *installReport) {
				r.Decision = "\u007f"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has DEL control character at edge",
			mutate: func(r *installReport) {
				r.Decision = "\u007fPASS"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Decision = "PASS\u200d"
			},
			detailHas: "decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "installed false",
			mutate: func(r *installReport) {
				r.Installed = false
			},
			detailHas: "installed must be true",
		},
		{
			name: "path mismatch",
			mutate: func(r *installReport) {
				r.InstalledPath = filepath.Join(skillPath, "other")
			},
			detailHas: "path mismatch",
		},
		{
			name: "installed path is empty",
			mutate: func(r *installReport) {
				r.InstalledPath = ""
			},
			detailHas: "installed path is empty",
		},
		{
			name: "installed path has surrounding whitespace",
			mutate: func(r *installReport) {
				r.InstalledPath = " " + r.InstalledPath + " "
			},
			detailHas: "installed path must not contain leading or trailing whitespace",
		},
		{
			name: "installed path has C0/C1 control character",
			mutate: func(r *installReport) {
				r.InstalledPath = filepath.Join(skillPath, "ok") + "\u008f"
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u0085" + skillPath
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u0085"
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has C0 NUL control character only",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u0000"
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has DEL control character only",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u007f"
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has DEL control character at edge",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u007f" + skillPath
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.InstalledPath = r.InstalledPath + "\u200d"
			},
			detailHas: "installed path must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := valid
			tc.mutate(&rep)
			mutRaw, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}
			writeReport(t, string(mutRaw))

			ok, detail := verifyInstallReport(skillPath, lock)
			if ok || !strings.Contains(detail, tc.detailHas) {
				t.Fatalf("expected detail containing %q, got ok=%v detail=%q", tc.detailHas, ok, detail)
			}
		})
	}

	t.Run("decision must be pass even when matching lock decision", func(t *testing.T) {
		rep := valid
		rep.Decision = "REJECTED"
		mutRaw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		writeReport(t, string(mutRaw))

		mutLock := lock
		mutLock.Policy.Decision = "REJECTED"
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "decision must be pass") {
			t.Fatalf("expected pass-decision enforcement, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("findings summary mismatch", func(t *testing.T) {
		validRaw, err := json.MarshalIndent(valid, "", "  ")
		if err != nil {
			t.Fatalf("marshal valid report: %v", err)
		}
		writeReport(t, string(validRaw))

		mutLock := lock
		mutLock.Findings = lockFindingSummary{High: 1}
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "findings summary does not match") {
			t.Fatalf("expected findings summary mismatch, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("severity overrides mismatch", func(t *testing.T) {
		rep := valid
		rep.SeverityOverrides = []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "approved for internal fixture",
				ApprovedBy:        "sec-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		}
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		writeReport(t, string(raw))

		mutLock := lock
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "severity_overrides does not match") {
			t.Fatalf("expected severity_overrides mismatch, got ok=%v detail=%q", ok, detail)
		}
	})
}
