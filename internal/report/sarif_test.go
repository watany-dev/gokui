package report

import "testing"

func TestSARIFLevelForSeverity(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{severity: "critical", want: "error"},
		{severity: "high", want: "error"},
		{severity: "medium", want: "warning"},
		{severity: "low", want: "note"},
		{severity: "unknown", want: "warning"},
	}
	for _, tc := range cases {
		if got := SARIFLevelForSeverity(tc.severity); got != tc.want {
			t.Fatalf("SARIFLevelForSeverity(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestSARIFMetadataConstants(t *testing.T) {
	if SARIFVersion != "2.1.0" {
		t.Fatalf("SARIFVersion = %q", SARIFVersion)
	}
	if SARIFSchema != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Fatalf("SARIFSchema = %q", SARIFSchema)
	}
	if SARIFDriverName != "gokui" {
		t.Fatalf("SARIFDriverName = %q", SARIFDriverName)
	}
	if SARIFDriverVersion != "pre-release" {
		t.Fatalf("SARIFDriverVersion = %q", SARIFDriverVersion)
	}
}

func TestSARIFErrorHelpers(t *testing.T) {
	rule := SARIFRuleForError("RULE_ONE", "ERROR_ONE")
	if rule.ID != "RULE_ONE" || rule.ShortDescription.Text != "ERROR_ONE" {
		t.Fatalf("SARIFRuleForError() = %+v", rule)
	}
	result := SARIFResultForError("RULE_ONE", "failed")
	if result.RuleID != "RULE_ONE" || result.Level != "error" || result.Message.Text != "failed" {
		t.Fatalf("SARIFResultForError() = %+v", result)
	}
}

func TestSARIFDocumentForRun(t *testing.T) {
	rules := []SARIFRule{SARIFRuleForError("RULE_ONE", "ERROR_ONE")}
	results := []SARIFResult{SARIFResultForError("RULE_ONE", "ok")}
	properties := SARIFProperties{SchemaVersion: "1", Decision: "PASS"}

	doc := SARIFDocumentForRun(rules, results, true, properties)
	if doc.Version != SARIFVersion || doc.Schema != SARIFSchema {
		t.Fatalf("unexpected SARIF metadata: %+v", doc)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != SARIFDriverName || run.Tool.Driver.Version != SARIFDriverVersion {
		t.Fatalf("unexpected driver: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "RULE_ONE" {
		t.Fatalf("unexpected rules: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 || run.Results[0].Message.Text != "ok" {
		t.Fatalf("unexpected results: %+v", run.Results)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("unexpected invocations: %+v", run.Invocations)
	}
	if run.Properties != properties {
		t.Fatalf("properties = %+v, want %+v", run.Properties, properties)
	}
}

func TestSARIFErrorDocument(t *testing.T) {
	properties := SARIFProperties{
		SchemaVersion: "1",
		PreRelease:    true,
		SourceInput:   "src",
		SourceKind:    "local-dir",
		Decision:      "ERROR",
		Note:          "note",
	}
	doc := SARIFErrorDocument("RULE_ONE", "ERROR_ONE", "failed", properties)
	if doc.Version != SARIFVersion || doc.Schema != SARIFSchema {
		t.Fatalf("unexpected SARIF metadata: %+v", doc)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != SARIFDriverName || run.Tool.Driver.Version != SARIFDriverVersion {
		t.Fatalf("unexpected driver: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "RULE_ONE" {
		t.Fatalf("unexpected rules: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 || run.Results[0].Message.Text != "failed" {
		t.Fatalf("unexpected results: %+v", run.Results)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("unexpected invocations: %+v", run.Invocations)
	}
	if run.Properties != properties {
		t.Fatalf("properties = %+v, want %+v", run.Properties, properties)
	}
}
