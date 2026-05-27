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
