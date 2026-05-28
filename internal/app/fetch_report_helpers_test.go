package app

import (
	"encoding/json"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	"strings"
	"testing"
)

func TestFetchHelperFunctions(t *testing.T) {
	if !argsRequestFormat([]string{"--format", "json"}, "json") {
		t.Fatal("expected json format detection")
	}
	if !argsRequestFormat([]string{"--format=json"}, "json") {
		t.Fatal("expected equals json format detection")
	}
	if argsRequestFormat([]string{"--format", "human"}, "json") {
		t.Fatal("human format should not be detected as json")
	}
	if !argsRequestFormat([]string{"--format", "sarif"}, "sarif") {
		t.Fatal("expected sarif format detection")
	}
	if !argsRequestFormat([]string{"--format=sarif"}, "sarif") {
		t.Fatal("expected equals sarif format detection")
	}
	if argsRequestFormat([]string{"--format", "human"}, "sarif") {
		t.Fatal("human format should not be detected as sarif")
	}

	if got := extractFetchSourceArg([]string{"--out", "/tmp/q", "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
	if got := extractFetchSourceArg([]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--format", "json"}); !strings.HasPrefix(got, "github:") {
		t.Fatalf("unexpected extracted source arg: %q", got)
	}
}

func TestBuildFetchCompactSummary(t *testing.T) {
	report := fetchReport{
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output:   "/tmp/q/x",
		Decision: "FETCHED",
	}
	got := buildFetchCompactSummary(report)
	required := []string{
		"fetch decision=FETCHED",
		"source_kind=github-source",
		"source=\"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\"",
		"output=\"/tmp/q/x\"",
	}
	for _, marker := range required {
		if !strings.Contains(got, marker) {
			t.Fatalf("compact summary missing marker %q: %q", marker, got)
		}
	}
}

func TestBuildFetchSARIFReport(t *testing.T) {
	report := fetchReport{
		SchemaVersion: reportSchemaVersion,
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output:   "/tmp/q/x",
		Decision: "FETCHED",
		Note:     "pre-release fetch note",
	}
	sarif := buildFetchSARIFReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Properties.Decision != "FETCHED" {
		t.Fatalf("decision = %q, want FETCHED", run.Properties.Decision)
	}
	if run.Properties.SourceKind != "github-source" {
		t.Fatalf("source kind = %q, want github-source", run.Properties.SourceKind)
	}
	if len(run.Results) != 0 {
		t.Fatalf("results should be empty, got %d", len(run.Results))
	}
}

func TestBuildFetchSARIFErrorReport(t *testing.T) {
	report := fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		Message:       "download failed",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Output: "/tmp/q/x",
		Note:   "fetch failed while downloading",
	}
	sarif := buildFetchSARIFErrorReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != fetchErrorCodeSourceDownloadFailed {
		t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, fetchErrorCodeSourceDownloadFailed)
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation executionSuccessful should be false, got %+v", run.Invocations)
	}
	if run.Properties.Decision != "ERROR" {
		t.Fatalf("decision = %q, want ERROR", run.Properties.Decision)
	}
}

func TestWriteFetchSARIFErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeFetchSARIFError(&stdout, &stderr, fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic fetch error",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Note: "test",
	})
	if code != 1 {
		t.Fatalf("writeFetchSARIFError() code = %d, want 1", code)
	}
	var sarif reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
		t.Fatalf("sarif parse failed: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif structure: %+v", sarif)
	}
	if sarif.Runs[0].Results[0].RuleID != "EXPLICIT_RULE" {
		t.Fatalf("rule id = %q, want EXPLICIT_RULE", sarif.Runs[0].Results[0].RuleID)
	}
}

func TestWriteFetchJSONErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeFetchJSONError(&stdout, &stderr, fetchErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     fetchErrorCodeSourceDownloadFailed,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic fetch error",
		Source: source{
			Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		},
		Note: "test",
	})
	if code != 1 {
		t.Fatalf("writeFetchJSONError() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \"EXPLICIT_RULE\"") {
		t.Fatalf("stdout should preserve explicit rule_id, got %q", stdout.String())
	}
}
