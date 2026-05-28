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

func TestSARIFDocumentForFindingsInput(t *testing.T) {
	doc := SARIFDocumentForFindingsInput(FindingsSARIFInput{
		SchemaVersion: "1",
		PreRelease:    true,
		SourceInput:   "./skill",
		SourceKind:    "local-dir",
		Decision:      "REJECTED",
		Rejected:      true,
		Note:          "note",
		Findings: []SARIFFinding{
			{ID: "RULE_A", Severity: "high", Summary: "first"},
		},
	})
	run := doc.Runs[0]
	if run.Invocations[0].ExecutionSuccessful {
		t.Fatal("rejected findings input should mark execution unsuccessful")
	}
	want := SARIFProperties{
		SchemaVersion: "1",
		PreRelease:    true,
		SourceInput:   "./skill",
		SourceKind:    "local-dir",
		Decision:      "REJECTED",
		Note:          "note",
	}
	if run.Properties != want {
		t.Fatalf("properties = %+v, want %+v", run.Properties, want)
	}
}

func TestPreReleaseSARIFProperties(t *testing.T) {
	got := PreReleaseSARIFProperties("1", "./skill", "local-dir", "PASS", "note")
	want := SARIFProperties{
		SchemaVersion: "1",
		PreRelease:    true,
		SourceInput:   "./skill",
		SourceKind:    "local-dir",
		Decision:      "PASS",
		Note:          "note",
	}
	if got != want {
		t.Fatalf("properties = %+v, want %+v", got, want)
	}
}

func TestPreReleaseSARIFErrorProperties(t *testing.T) {
	got := PreReleaseSARIFErrorProperties("1", "./skill", "local-dir", "ERROR", "failed", "ERROR_CODE")
	want := SARIFProperties{
		SchemaVersion: "1",
		PreRelease:    true,
		SourceInput:   "./skill",
		SourceKind:    "local-dir",
		Decision:      "ERROR",
		Note:          "failed; error_code=ERROR_CODE",
	}
	if got != want {
		t.Fatalf("properties = %+v, want %+v", got, want)
	}
}

func TestSARIFDocumentForLockVerify(t *testing.T) {
	doc := SARIFDocumentForLockVerify(LockVerifySARIFInput{
		Status:         "DRIFTED",
		VerifiedStatus: "VERIFIED",
		FileDigestCode: "FILE_DIGESTS",
		Checks: []LockVerifySARIFCheck{
			{Code: "SCHEMA", Name: "schema", OK: true, Detail: "ok"},
			{Code: "FILE_DIGESTS", Name: "file digests", OK: false, Detail: "missing=1 changed=1 unexpected=1"},
		},
		Drift: LockVerifySARIFDrift{
			MissingFiles:    []string{"missing.md"},
			ChangedFiles:    []string{"changed.md"},
			UnexpectedFiles: []string{"extra.md"},
		},
		Properties: SARIFProperties{
			SchemaVersion: "1",
			PreRelease:    true,
			SourceInput:   "/tmp/skill",
			SourceKind:    "installed-skill",
			Note:          "lock verify",
		},
	})
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || run.Tool.Driver.Rules[0].ID != "FILE_DIGESTS" || run.Tool.Driver.Rules[1].ID != "SCHEMA" {
		t.Fatalf("rules not sorted: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results len = %d, want 4: %+v", len(run.Results), run.Results)
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Fatal("drifted lock verify should not be execution successful")
	}
	if run.Properties.Decision != "DRIFTED" {
		t.Fatalf("decision = %q, want DRIFTED", run.Properties.Decision)
	}
	var foundMissing bool
	for _, result := range run.Results {
		if result.Message.Text == "missing file listed in lock: missing.md" && len(result.Locations) == 1 {
			foundMissing = true
		}
	}
	if !foundMissing {
		t.Fatalf("missing drift result not found: %+v", run.Results)
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

func TestSARIFSortHelpers(t *testing.T) {
	rules := []SARIFRule{
		SARIFRuleForFinding("RULE_B", "b"),
		SARIFRuleForFinding("RULE_A", "a"),
	}
	SortSARIFRulesByID(rules)
	if rules[0].ID != "RULE_A" || rules[1].ID != "RULE_B" {
		t.Fatalf("rules not sorted: %+v", rules)
	}

	results := []SARIFResult{
		SARIFResultForFinding("RULE_B", "error", "z", []SARIFLocation{SARIFLocationForFile("b.txt", 0)}),
		SARIFResultForFinding("RULE_A", "error", "z", nil),
		SARIFResultForFinding("RULE_B", "error", "a", []SARIFLocation{SARIFLocationForFile("b.txt", 0)}),
		SARIFResultForFinding("RULE_B", "error", "z", []SARIFLocation{SARIFLocationForFile("a.txt", 0)}),
	}
	SortSARIFResultsByRuleLocationMessage(results)
	if results[0].RuleID != "RULE_A" || results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI != "a.txt" || results[2].Message.Text != "a" {
		t.Fatalf("results not sorted: %+v", results)
	}
	if got := SARIFResultLocationURI(results[0]); got != "" {
		t.Fatalf("location uri = %q, want empty", got)
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

func TestSARIFErrorDocumentForInput(t *testing.T) {
	doc := SARIFErrorDocumentForInput(SARIFErrorInput{
		RuleID:        "RULE_ONE",
		ErrorCode:     "ERROR_ONE",
		Message:       "failed",
		SchemaVersion: "1",
		SourceInput:   "src",
		SourceKind:    "local-dir",
		Decision:      "ERROR",
		Note:          "note",
	})
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "RULE_ONE" {
		t.Fatalf("unexpected rules: %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 1 || run.Results[0].RuleID != "RULE_ONE" || run.Results[0].Message.Text != "failed" {
		t.Fatalf("unexpected results: %+v", run.Results)
	}
	properties := PreReleaseSARIFErrorProperties("1", "src", "local-dir", "ERROR", "note", "ERROR_ONE")
	if run.Properties != properties {
		t.Fatalf("properties = %+v, want %+v", run.Properties, properties)
	}
}
