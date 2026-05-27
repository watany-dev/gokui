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
