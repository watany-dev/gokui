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
	findingRule := SARIFRuleForFinding("RULE_FINDING", "finding summary")
	if findingRule.ID != "RULE_FINDING" || findingRule.ShortDescription.Text != "finding summary" {
		t.Fatalf("SARIFRuleForFinding() = %+v", findingRule)
	}
	rule := SARIFRuleForError("RULE_ONE", "ERROR_ONE")
	if rule.ID != "RULE_ONE" || rule.ShortDescription.Text != "ERROR_ONE" {
		t.Fatalf("SARIFRuleForError() = %+v", rule)
	}
	location := SARIFLocationForFile("file.md", 3)
	findingResult := SARIFResultForFinding("RULE_FINDING", "warning", "finding message", []SARIFLocation{location})
	if findingResult.RuleID != "RULE_FINDING" || findingResult.Level != "warning" || findingResult.Message.Text != "finding message" || len(findingResult.Locations) != 1 {
		t.Fatalf("SARIFResultForFinding() = %+v", findingResult)
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

func TestSARIFDocumentForFindings(t *testing.T) {
	properties := SARIFProperties{SchemaVersion: "1", Decision: "PASS"}
	findings := []SARIFFinding{
		{ID: "RULE_B", Severity: "low", File: "b.txt", Line: 12, Summary: "second"},
		{ID: "RULE_A", Severity: "high", Summary: "first"},
		{ID: "RULE_B", Severity: "medium", File: "other.txt", Summary: "duplicate rule"},
	}

	doc := SARIFDocumentForFindings(findings, true, properties)
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "RULE_A" || run.Tool.Driver.Rules[1].ID != "RULE_B" {
		t.Fatalf("rules not sorted/deduplicated: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 3 {
		t.Fatalf("results len = %d, want 3", len(run.Results))
	}
	if run.Results[0].Level != "note" || len(run.Results[0].Locations) != 1 {
		t.Fatalf("unexpected first result: %+v", run.Results[0])
	}
	if got := run.Results[0].Locations[0].PhysicalLocation.Region.StartLine; got != 12 {
		t.Fatalf("startLine = %d, want 12", got)
	}
	if run.Results[1].Level != "error" || len(run.Results[1].Locations) != 0 {
		t.Fatalf("unexpected second result: %+v", run.Results[1])
	}
	if run.Properties != properties {
		t.Fatalf("properties = %+v, want %+v", run.Properties, properties)
	}
}

func TestSARIFLocationForFile(t *testing.T) {
	location := SARIFLocationForFile("path/to/file.md", 7)
	if got := location.PhysicalLocation.ArtifactLocation.URI; got != "path/to/file.md" {
		t.Fatalf("uri = %q, want path/to/file.md", got)
	}
	if location.PhysicalLocation.Region == nil || location.PhysicalLocation.Region.StartLine != 7 {
		t.Fatalf("region = %+v, want startLine 7", location.PhysicalLocation.Region)
	}

	location = SARIFLocationForFile("path/to/file.md", 0)
	if location.PhysicalLocation.Region != nil {
		t.Fatalf("region = %+v, want nil", location.PhysicalLocation.Region)
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
