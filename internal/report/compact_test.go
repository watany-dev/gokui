package report

import (
	"strings"
	"testing"
)

func TestCountSeverities(t *testing.T) {
	got := CountSeverities([]string{"critical", "high", "high", "medium", "low", "unknown"})
	want := SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1}
	if got != want {
		t.Fatalf("CountSeverities() = %+v, want %+v", got, want)
	}
}

func TestInspectCompactSummary(t *testing.T) {
	got := InspectCompactSummary("REJECTED", "local-dir", "skill path", []string{"critical", "low"})
	required := []string{
		"inspect decision=REJECTED",
		"findings=2",
		"critical=1",
		"high=0",
		"medium=0",
		"low=1",
		"source_kind=local-dir",
		`source="skill path"`,
	}
	for _, token := range required {
		if !strings.Contains(got, token) {
			t.Fatalf("summary should include %q, got %q", token, got)
		}
	}
}

func TestFetchCompactSummary(t *testing.T) {
	got := FetchCompactSummary("FETCHED", "github-source", "github:org/repo//skill@abc", "/tmp/q/skill")
	required := []string{
		"fetch decision=FETCHED",
		"source_kind=github-source",
		`source="github:org/repo//skill@abc"`,
		`output="/tmp/q/skill"`,
	}
	for _, token := range required {
		if !strings.Contains(got, token) {
			t.Fatalf("summary should include %q, got %q", token, got)
		}
	}
}
