package report

import "fmt"

type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

func CountSeverities(severities []string) SeverityCounts {
	counts := SeverityCounts{}
	for _, severity := range severities {
		switch severity {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		}
	}
	return counts
}

func InspectCompactSummary(decision string, sourceKind string, sourceInput string, severities []string) string {
	counts := CountSeverities(severities)
	return fmt.Sprintf(
		"inspect decision=%s findings=%d critical=%d high=%d medium=%d low=%d source_kind=%s source=%q",
		decision,
		len(severities),
		counts.Critical,
		counts.High,
		counts.Medium,
		counts.Low,
		sourceKind,
		sourceInput,
	)
}

func FetchCompactSummary(decision string, sourceKind string, sourceInput string, output string) string {
	return fmt.Sprintf(
		"fetch decision=%s source_kind=%s source=%q output=%q",
		decision,
		sourceKind,
		sourceInput,
		output,
	)
}

type InstallCompactInput struct {
	Decision      string
	Severities    []string
	Overrides     int
	Installed     bool
	PolicyProfile string
	Target        string
	SourceKind    string
	SourceInput   string
	ErrorCode     string
}

func InstallCompactSummary(input InstallCompactInput) string {
	counts := CountSeverities(input.Severities)
	return fmt.Sprintf(
		"install decision=%s findings=%d critical=%d high=%d medium=%d low=%d overrides=%d installed=%t profile=%s target=%q source_kind=%s source=%q error_code=%s",
		input.Decision,
		len(input.Severities),
		counts.Critical,
		counts.High,
		counts.Medium,
		counts.Low,
		input.Overrides,
		input.Installed,
		input.PolicyProfile,
		input.Target,
		input.SourceKind,
		input.SourceInput,
		input.ErrorCode,
	)
}
