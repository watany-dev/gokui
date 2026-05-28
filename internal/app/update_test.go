package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseUpdateArgs(t *testing.T) {
	t.Run("parses required dry-run with defaults", func(t *testing.T) {
		got, err := parseUpdateArgs([]string{"--dry-run"})
		if err != nil {
			t.Fatalf("parseUpdateArgs() error = %v", err)
		}
		if !got.DryRun || got.Target != "codex" || got.Format != "human" {
			t.Fatalf("unexpected parsed args: %+v", got)
		}
	})

	t.Run("parses explicit target and json format", func(t *testing.T) {
		got, err := parseUpdateArgs([]string{"--dry-run", "--target=custom:/tmp/skills", "--format=json"})
		if err != nil {
			t.Fatalf("parseUpdateArgs() error = %v", err)
		}
		if got.Target != "custom:/tmp/skills" || got.Format != "json" {
			t.Fatalf("unexpected parsed args: %+v", got)
		}
	})

	t.Run("parses sarif format", func(t *testing.T) {
		got, err := parseUpdateArgs([]string{"--dry-run", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseUpdateArgs() error = %v", err)
		}
		if got.Format != "sarif" {
			t.Fatalf("format = %q, want %q", got.Format, "sarif")
		}
	})

	t.Run("parses compact format", func(t *testing.T) {
		got, err := parseUpdateArgs([]string{"--dry-run", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseUpdateArgs() error = %v", err)
		}
		if got.Format != "compact" {
			t.Fatalf("format = %q, want %q", got.Format, "compact")
		}
	})

	t.Run("errors", func(t *testing.T) {
		_, err := parseUpdateArgs(nil)
		if err == nil || !strings.Contains(err.Error(), "requires --dry-run") {
			t.Fatalf("expected dry-run required error, got %v", err)
		}

		_, err = parseUpdateArgs([]string{"--dry-run", "--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported update format") {
			t.Fatalf("expected format error, got %v", err)
		}

		_, err = parseUpdateArgs([]string{"--dry-run", "--target"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --target") {
			t.Fatalf("expected target value error, got %v", err)
		}
		_, err = parseUpdateArgs([]string{"--dry-run", "--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected format value error, got %v", err)
		}

		_, err = parseUpdateArgs([]string{"--dry-run", "./skill"})
		if err == nil || !strings.Contains(err.Error(), "does not accept positional arguments") {
			t.Fatalf("expected positional arg error, got %v", err)
		}

		_, err = parseUpdateArgs([]string{"--dry-run", "--unknown"})
		if err == nil || !strings.Contains(err.Error(), "unknown update option") {
			t.Fatalf("expected unknown option error, got %v", err)
		}
	})
}

func TestWriteUpdateJSONErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeUpdateJSONError(&stdout, &stderr, updateErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     updateFatalCodeReportBuild,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic update error",
		Target:        "/tmp/skills",
		Note:          "test",
	})
	if code != 1 {
		t.Fatalf("writeUpdateJSONError() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \"EXPLICIT_RULE\"") {
		t.Fatalf("stdout should preserve explicit rule_id, got %q", stdout.String())
	}
}

func TestIsUpdateTargetReadError(t *testing.T) {
	t.Run("matches sentinel and wrapped sentinel", func(t *testing.T) {
		if !isUpdateTargetReadError(errUpdateTargetRead) {
			t.Fatal("expected sentinel to match")
		}
		wrapped := fmt.Errorf("wrapped: %w", errUpdateTargetRead)
		if !isUpdateTargetReadError(wrapped) {
			t.Fatal("expected wrapped sentinel to match")
		}
	})

	t.Run("does not match text-only error", func(t *testing.T) {
		err := errors.New("failed to read update target: /tmp/skills")
		if isUpdateTargetReadError(err) {
			t.Fatal("did not expect text-only error to match")
		}
	})
}

func TestClassifyUpdateSourcePrepareFailure(t *testing.T) {
	t.Run("github pinned-ref sentinel maps to rejected floating-ref code", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", errGitHubRefNotPinned)
		status, code := classifyUpdateSourcePrepareFailure("github-source", err)
		if status != "REJECTED" || code != updateCodeGitHubRefFloating {
			t.Fatalf("unexpected classification: status=%q code=%q", status, code)
		}
	})

	t.Run("text-only commit-pinned phrase does not trigger rejected mapping", func(t *testing.T) {
		err := errors.New("github source requires a commit-pinned ref")
		status, code := classifyUpdateSourcePrepareFailure("github-source", err)
		if status != "ERROR" || code != updateCodeSourcePrepareError {
			t.Fatalf("unexpected classification: status=%q code=%q", status, code)
		}
	})

	t.Run("non-github source stays source-prepare error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", errGitHubRefNotPinned)
		status, code := classifyUpdateSourcePrepareFailure("local-dir", err)
		if status != "ERROR" || code != updateCodeSourcePrepareError {
			t.Fatalf("unexpected classification: status=%q code=%q", status, code)
		}
	})
}

func TestFailUpdateSkillItem(t *testing.T) {
	lock := installLock{
		Findings: lockFindingSummary{
			Critical: 1,
			High:     2,
			Medium:   3,
			Low:      4,
		},
	}
	item := updateSkillItem{Name: "demo"}

	got := failUpdateSkillItem(item, lock, "ERROR", updateCodeLockfileInvalid, "LOCKFILE_INVALID_UTF8: lock policy decision must be canonical lowercase pass")
	if got.Name != item.Name {
		t.Fatalf("name = %q, want %q", got.Name, item.Name)
	}
	if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
		t.Fatalf("status/code = %q/%q", got.Status, got.ErrorCode)
	}
	if got.Message != "LOCKFILE_INVALID_UTF8: lock policy decision must be canonical lowercase pass" {
		t.Fatalf("message = %q", got.Message)
	}
	if got.RuleID != "LOCKFILE_INVALID_UTF8" {
		t.Fatalf("rule_id = %q, want LOCKFILE_INVALID_UTF8", got.RuleID)
	}
	if got.Risk.Previous != lock.Findings || got.Risk.Current != lock.Findings {
		t.Fatalf("risk summary mismatch: %+v", got.Risk)
	}
}

func TestValidateUpdateLockEnvelopeAdditionalBranches(t *testing.T) {
	valid := installLock{
		Schema:      lockSchemaVersion,
		Name:        "demo",
		InstalledAt: "2026-05-24T00:00:00Z",
		Policy: lockPolicy{
			SeverityOverrides: []severityOverrideAudit{},
		},
	}

	cases := []struct {
		name   string
		mutate func(*installLock)
		want   string
	}{
		{
			name:   "name surrounding whitespace",
			mutate: func(lock *installLock) { lock.Name = " demo " },
			want:   "lock name must not contain leading or trailing whitespace",
		},
		{
			name:   "installed_at empty",
			mutate: func(lock *installLock) { lock.InstalledAt = "" },
			want:   "lock installed_at is empty",
		},
		{
			name:   "installed_at surrounding whitespace",
			mutate: func(lock *installLock) { lock.InstalledAt = " 2026-05-24T00:00:00Z " },
			want:   "lock installed_at must not contain leading or trailing whitespace",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lock := valid
			tc.mutate(&lock)
			err := validateUpdateLockEnvelope(lock, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}

func TestBuildUpdateSARIFReport(t *testing.T) {
	t.Run("builds rules and results from findings and status errors", func(t *testing.T) {
		report := updateReport{
			SchemaVersion: reportSchemaVersion,
			Target:        "/tmp/skills",
			DryRun:        true,
			Note:          "test note",
			Summary: updateSummary{
				Total:    4,
				UpToDate: 1,
				Changed:  1,
				Rejected: 1,
				Errors:   1,
			},
			Skills: []updateSkillItem{
				{
					Name:   "alpha",
					Status: "CHANGED",
					Findings: []inspectFinding{
						{ID: "PROMPT_OVERRIDE_LANGUAGE", Severity: "high", File: "SKILL.md", Line: 12, Summary: "prompt override language detected"},
						{ID: "REMOTE_IMAGE_URL", Severity: "medium", File: "README.md", Line: 3, Summary: "remote image URL detected"},
					},
				},
				{
					Name:      "beta",
					Status:    "ERROR",
					ErrorCode: updateCodeEvaluationError,
					RuleID:    "UPDATE_URL_SCAN_SPECIAL_FILE",
					Message:   "UPDATE_URL_SCAN_SPECIAL_FILE: URL scan input contains non-regular file",
				},
				{
					Name:      "gamma",
					Status:    "REJECTED",
					ErrorCode: updateCodePolicyRejected,
					Message:   "fresh policy evaluation rejected update source",
				},
				{
					Name:      "delta",
					Status:    "UP_TO_DATE",
					ErrorCode: updateCodeUpToDate,
					Message:   "no change",
				},
			},
		}

		sarif := buildUpdateSARIFReport(report)
		if sarif.Version != "2.1.0" {
			t.Fatalf("version = %q, want 2.1.0", sarif.Version)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("runs length = %d, want 1", len(sarif.Runs))
		}
		run := sarif.Runs[0]
		if run.Properties.SourceKind != "update-target" {
			t.Fatalf("source_kind = %q, want update-target", run.Properties.SourceKind)
		}
		if run.Properties.Decision != "ERROR" {
			t.Fatalf("decision = %q, want ERROR", run.Properties.Decision)
		}
		if len(run.Results) == 0 {
			t.Fatal("expected sarif results")
		}

		hasPrompt := false
		hasStatusError := false
		hasStatusRejected := false
		for _, result := range run.Results {
			switch result.RuleID {
			case "PROMPT_OVERRIDE_LANGUAGE":
				hasPrompt = true
				if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.Region == nil {
					t.Fatalf("finding result should include location with region: %+v", result)
				}
			case "UPDATE_URL_SCAN_SPECIAL_FILE":
				hasStatusError = true
			case updateCodePolicyRejected:
				hasStatusRejected = true
			}
		}
		if !hasPrompt || !hasStatusError || !hasStatusRejected {
			t.Fatalf("missing expected result ids, got %+v", run.Results)
		}
		if run.Invocations[0].ExecutionSuccessful {
			t.Fatalf("execution_successful should be false when errors/rejected exist")
		}
	})

	t.Run("decision falls back to rejected/changed/pass", func(t *testing.T) {
		rejected := buildUpdateSARIFReport(updateReport{
			SchemaVersion: reportSchemaVersion,
			Target:        "/tmp/skills",
			Summary:       updateSummary{Total: 1, Rejected: 1},
		})
		if rejected.Runs[0].Properties.Decision != "REJECTED" {
			t.Fatalf("decision = %q, want REJECTED", rejected.Runs[0].Properties.Decision)
		}

		changed := buildUpdateSARIFReport(updateReport{
			SchemaVersion: reportSchemaVersion,
			Target:        "/tmp/skills",
			Summary:       updateSummary{Total: 1, Changed: 1},
		})
		if changed.Runs[0].Properties.Decision != "CHANGED" {
			t.Fatalf("decision = %q, want CHANGED", changed.Runs[0].Properties.Decision)
		}
		if !changed.Runs[0].Invocations[0].ExecutionSuccessful {
			t.Fatalf("execution_successful should remain true when no errors/rejections")
		}

		pass := buildUpdateSARIFReport(updateReport{
			SchemaVersion: reportSchemaVersion,
			Target:        "/tmp/skills",
			Summary:       updateSummary{Total: 1, UpToDate: 1},
		})
		if pass.Runs[0].Properties.Decision != "PASS" {
			t.Fatalf("decision = %q, want PASS", pass.Runs[0].Properties.Decision)
		}
	})

	t.Run("covers fallback rule/message and deterministic sorting", func(t *testing.T) {
		report := updateReport{
			SchemaVersion: reportSchemaVersion,
			Target:        "/tmp/skills",
			Summary:       updateSummary{Total: 3, Errors: 1},
			Skills: []updateSkillItem{
				{
					Name:   "zeta",
					Status: "CHANGED",
					Findings: []inspectFinding{
						{ID: "A_RULE", Severity: "medium", File: "b.md", Line: 10, Summary: "b"},
						{ID: "A_RULE", Severity: "medium", File: "a.md", Line: 2, Summary: "a"},
						{ID: "A_RULE", Severity: "medium", File: "same.md", Line: 20, Summary: "line-20"},
						{ID: "A_RULE", Severity: "medium", File: "same.md", Line: 5, Summary: "line-5"},
						{ID: "B_RULE", Severity: "low", File: "", Line: 0, Summary: ""},
					},
				},
				{
					Name:      "omega",
					Status:    "ERROR",
					ErrorCode: "",
					RuleID:    "",
					Message:   "   ",
				},
				{
					Name:   "skip-me",
					Status: "UP_TO_DATE",
				},
			},
		}

		sarif := buildUpdateSARIFReport(report)
		if len(sarif.Runs) != 1 {
			t.Fatalf("runs length = %d, want 1", len(sarif.Runs))
		}
		run := sarif.Runs[0]
		if len(run.Results) < 4 {
			t.Fatalf("expected at least 4 results, got %d", len(run.Results))
		}
		if run.Results[0].RuleID > run.Results[len(run.Results)-1].RuleID {
			t.Fatalf("results should be sorted by rule id")
		}

		foundFallback := false
		foundEmptySummaryRule := false
		for _, rule := range run.Tool.Driver.Rules {
			if rule.ID == "UPDATE_SKILL_STATUS" {
				foundFallback = true
			}
			if rule.ID == "B_RULE" && strings.Contains(rule.ShortDescription.Text, "finding in zeta") {
				foundEmptySummaryRule = true
			}
		}
		if !foundFallback {
			t.Fatalf("expected UPDATE_SKILL_STATUS fallback rule, got %+v", run.Tool.Driver.Rules)
		}
		if !foundEmptySummaryRule {
			t.Fatalf("expected empty-summary fallback text for B_RULE, got %+v", run.Tool.Driver.Rules)
		}
	})
}
