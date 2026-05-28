package report

import (
	"strings"
	"testing"
)

func TestNeutralizeReviewText(t *testing.T) {
	got := NeutralizeReviewText("line1\nline2 \u202E hidden")
	if !strings.Contains(got, `\n`) {
		t.Fatalf("expected escaped newline, got %q", got)
	}
	if strings.ContainsRune(got, '\u202e') {
		t.Fatalf("expected bidi rune to be escaped, got %q", got)
	}
	if !strings.Contains(got, `\u202e`) {
		t.Fatalf("expected ASCII unicode escape, got %q", got)
	}
}

func TestNeutralizeReviewTextInvalidUTF8(t *testing.T) {
	got := NeutralizeReviewText(string([]byte{'o', 'k', 0xff}))
	if strings.ContainsRune(got, '\ufffd') {
		t.Fatalf("replacement rune should be escaped, got %q", got)
	}
	if !strings.Contains(got, `\ufffd`) {
		t.Fatalf("expected escaped replacement rune, got %q", got)
	}
}

func TestReviewFindings(t *testing.T) {
	findings, summary := ReviewFindings([]ReviewFindingInput{
		{ID: "A", Severity: "high", File: "SKILL.md", Line: 1, Summary: "line1\nline2"},
		{ID: "B", Severity: "medium", File: "README.md", Line: 2, Summary: "\u202E hidden"},
		{ID: "C", Severity: "low", File: "notes.md", Line: 3, Summary: "ok"},
	})
	if summary.Total != 3 || summary.High != 1 || summary.Medium != 1 || summary.Low != 1 {
		t.Fatalf("summary = %+v, want one high/medium/low", summary)
	}
	if len(findings) != 3 {
		t.Fatalf("findings len = %d, want 3", len(findings))
	}
	if !strings.Contains(findings[0].SummaryNeutralized, `\n`) {
		t.Fatalf("expected escaped newline, got %q", findings[0].SummaryNeutralized)
	}
	if strings.ContainsRune(findings[1].SummaryNeutralized, '\u202e') || !strings.Contains(findings[1].SummaryNeutralized, `\u202e`) {
		t.Fatalf("expected escaped bidi rune, got %q", findings[1].SummaryNeutralized)
	}
}
