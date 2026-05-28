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

func TestInstallCompactSummary(t *testing.T) {
	got := InstallCompactSummary(InstallCompactInput{
		Decision:      "REJECTED",
		Severities:    []string{"critical", "high", "medium", "low", "info"},
		Overrides:     1,
		Installed:     false,
		PolicyProfile: "strict",
		Target:        "custom:/tmp/skills",
		SourceKind:    "local-dir",
		SourceInput:   "/tmp/skill",
		ErrorCode:     "POLICY_REJECTED",
	})
	required := []string{
		"install decision=REJECTED",
		"findings=5",
		"critical=1",
		"high=1",
		"medium=1",
		"low=1",
		"overrides=1",
		"installed=false",
		"profile=strict",
		`target="custom:/tmp/skills"`,
		"source_kind=local-dir",
		`source="/tmp/skill"`,
		"error_code=POLICY_REJECTED",
	}
	for _, token := range required {
		if !strings.Contains(got, token) {
			t.Fatalf("summary should include %q, got %q", token, got)
		}
	}
}

func TestUpdateCompactSummary(t *testing.T) {
	got := UpdateCompactSummary(UpdateCompactInput{
		Total:    5,
		UpToDate: 1,
		Changed:  2,
		Rejected: 1,
		Skipped:  0,
		Errors:   1,
		Target:   "codex",
	})
	required := []string{
		"update total=5",
		"up_to_date=1",
		"changed=2",
		"rejected=1",
		"skipped=0",
		"errors=1",
		`target="codex"`,
	}
	for _, token := range required {
		if !strings.Contains(got, token) {
			t.Fatalf("summary should include %q, got %q", token, got)
		}
	}
}
