package report

import (
	"strconv"
	"strings"
)

// ReviewFindingInput is the package-neutral input shape for a review finding.
type ReviewFindingInput struct {
	ID       string
	Severity string
	File     string
	Line     int
	Summary  string
}

// ReviewFinding is a neutralized finding ready for review-oriented output.
type ReviewFinding struct {
	ID                 string
	Severity           string
	FileNeutralized    string
	Line               int
	SummaryNeutralized string
}

// ReviewSummary counts review findings by severity.
type ReviewSummary struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

// NeutralizeReviewText escapes untrusted text before it is emitted into
// review-oriented JSON intended for display in code review systems.
func NeutralizeReviewText(text string) string {
	valid := strings.ToValidUTF8(text, "\uFFFD")
	quoted := strconv.QuoteToASCII(valid)
	return quoted[1 : len(quoted)-1]
}

func ReviewFindings(inputs []ReviewFindingInput) ([]ReviewFinding, ReviewSummary) {
	findings := make([]ReviewFinding, 0, len(inputs))
	summary := ReviewSummary{}
	for _, input := range inputs {
		findings = append(findings, ReviewFinding{
			ID:                 input.ID,
			Severity:           input.Severity,
			FileNeutralized:    NeutralizeReviewText(input.File),
			Line:               input.Line,
			SummaryNeutralized: NeutralizeReviewText(input.Summary),
		})
		summary.Total++
		switch input.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}
	return findings, summary
}
