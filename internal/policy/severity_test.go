package policy

import "testing"

func TestSeverityHelpers(t *testing.T) {
	if got := NormalizeSeverity(" HIGH "); got != SeverityHigh {
		t.Fatalf("NormalizeSeverity() = %q, want %q", got, SeverityHigh)
	}
	if got := SeverityMedium.String(); got != "medium" {
		t.Fatalf("SeverityMedium.String() = %q", got)
	}
	for _, severity := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		if !severity.IsCanonical() {
			t.Fatalf("%q should be canonical", severity)
		}
	}
	if NormalizeSeverity("warn").IsCanonical() {
		t.Fatal("warn should not be canonical")
	}
	if got, err := ParseSeverity(" low "); err != nil || got != SeverityLow {
		t.Fatalf("ParseSeverity(low) = %q, %v", got, err)
	}
	if _, err := ParseSeverity("warn"); err == nil {
		t.Fatal("ParseSeverity should reject unsupported severity")
	}
}

func TestSeveritySetStrings(t *testing.T) {
	set := SeveritySet{SeverityCritical: {}, SeverityHigh: {}}
	got := set.Strings()
	if len(got) != 2 {
		t.Fatalf("Strings() length = %d, want 2", len(got))
	}
	if _, ok := got["critical"]; !ok {
		t.Fatal("Strings() should include critical")
	}
	if _, ok := got["high"]; !ok {
		t.Fatal("Strings() should include high")
	}
}
