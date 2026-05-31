package app

import (
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestResolveInstallOutputReportUsesPersistedReportOnIdempotentReuse(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "persisted-report-output")
	targetRoot := t.TempDir()
	baseReport := installReport{
		SchemaVersion: reportSchemaVersion,
		Source: source{
			Input: src,
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		SeverityOverrides: []policypkg.SeverityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "test fixture",
				ApprovedBy:        "test",
				Source:            "cli-override",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		},
	}

	installedPath, result, err := installSkillAtomic(src, targetRoot, "persisted-report-output", baseReport)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}
	if result != installResultInstalled {
		t.Fatalf("result = %q, want %q", result, installResultInstalled)
	}

	staleReport := baseReport
	staleReport.SeverityOverrides = nil
	staleReport.Findings = []inspectFinding{
		{
			ID:       "OTHER_RULE",
			Severity: policypkg.SeverityHigh,
			File:     "SKILL.md",
			Line:     1,
			Summary:  "stale evaluation should not appear in output",
		},
	}

	output := resolveInstallOutputReport(installedPath, installResultAlreadyInstalled, staleReport)
	if len(output.SeverityOverrides) != 1 {
		t.Fatalf("severity_overrides length = %d, want 1 from persisted report", len(output.SeverityOverrides))
	}
	if output.SeverityOverrides[0].RuleID != "PROMPT_OVERRIDE_LANGUAGE" {
		t.Fatalf("override rule_id = %q", output.SeverityOverrides[0].RuleID)
	}
	if len(output.Findings) == 1 && output.Findings[0].ID == "OTHER_RULE" {
		t.Fatalf("output findings came from stale evaluation, want persisted report")
	}
}
