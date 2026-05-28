package app

import (
	"strings"
	"testing"
)

func TestBuildLockVerifySARIFReport(t *testing.T) {
	report := lockVerifyReport{
		SchemaVersion: reportSchemaVersion,
		SkillPath:     "/tmp/skills/demo",
		Status:        "DRIFTED",
		Checks: []lockVerifyCheck{
			{Code: lockVerifyCodeSchema, Name: "schema", OK: true, Detail: "ok"},
			{Code: lockVerifyCodeFileDigests, Name: "file_digests", OK: false, Detail: "missing=1 changed=1 unexpected=1"},
		},
		Drift: lockVerifyDriftInfo{
			MissingFiles:    []string{"missing.md"},
			ChangedFiles:    []string{"changed.md"},
			UnexpectedFiles: []string{"extra.md"},
		},
		Note: "test",
	}

	sarif := buildLockVerifySARIFReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Properties.Decision != "DRIFTED" {
		t.Fatalf("decision = %q, want DRIFTED", run.Properties.Decision)
	}
	if run.Properties.SourceKind != "installed-skill" {
		t.Fatalf("source_kind = %q, want installed-skill", run.Properties.SourceKind)
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Fatal("executionSuccessful should be false for drifted report")
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("expected rules in sarif driver")
	}

	foundSummary := false
	foundMissing := false
	foundChanged := false
	foundUnexpected := false
	for _, result := range run.Results {
		if result.RuleID != lockVerifyCodeFileDigests {
			continue
		}
		switch {
		case strings.Contains(result.Message.Text, "missing=1 changed=1 unexpected=1"):
			foundSummary = true
		case strings.Contains(result.Message.Text, "missing file listed in lock") && strings.Contains(result.Message.Text, "missing.md"):
			foundMissing = true
		case strings.Contains(result.Message.Text, "changed file hash or size") && strings.Contains(result.Message.Text, "changed.md"):
			foundChanged = true
		case strings.Contains(result.Message.Text, "unexpected file not listed in lock") && strings.Contains(result.Message.Text, "extra.md"):
			foundUnexpected = true
		}
	}
	if !foundSummary || !foundMissing || !foundChanged || !foundUnexpected {
		t.Fatalf("missing expected digest drift results: %+v", run.Results)
	}
}

func TestBuildLockVerifyCompactSummary(t *testing.T) {
	report := lockVerifyReport{
		SkillPath: "/tmp/skills/demo",
		Status:    "DRIFTED",
		Checks: []lockVerifyCheck{
			{Code: lockVerifyCodeSchema, Name: "schema", OK: true, Detail: "ok"},
			{Code: lockVerifyCodeFileDigests, Name: "file_digests", OK: false, Detail: "missing=1 changed=1 unexpected=1"},
			{Code: lockVerifyCodeRootHash, Name: "root_hash", OK: false, Detail: "hash mismatch"},
		},
		Drift: lockVerifyDriftInfo{
			MissingFiles:    []string{"a.md"},
			ChangedFiles:    []string{"b.md"},
			UnexpectedFiles: []string{"c.md", "d.md"},
		},
	}
	got := buildLockVerifyCompactSummary(report)
	required := []string{
		"lock_verify status=DRIFTED",
		"checks=3",
		"failed=2",
		"missing=1",
		"changed=1",
		"unexpected=2",
		"path=\"/tmp/skills/demo\"",
	}
	for _, marker := range required {
		if !strings.Contains(got, marker) {
			t.Fatalf("compact summary missing marker %q: %q", marker, got)
		}
	}
}
