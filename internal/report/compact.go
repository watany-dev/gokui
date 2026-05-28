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

type UpdateCompactInput struct {
	Total    int
	UpToDate int
	Changed  int
	Rejected int
	Skipped  int
	Errors   int
	Target   string
}

func UpdateCompactSummary(input UpdateCompactInput) string {
	return fmt.Sprintf(
		"update total=%d up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d target=%q",
		input.Total,
		input.UpToDate,
		input.Changed,
		input.Rejected,
		input.Skipped,
		input.Errors,
		input.Target,
	)
}

type LockVerifyCompactInput struct {
	Status          string
	Checks          int
	Failed          int
	MissingFiles    int
	ChangedFiles    int
	UnexpectedFiles int
	Path            string
}

func LockVerifyCompactSummary(input LockVerifyCompactInput) string {
	return fmt.Sprintf(
		"lock_verify status=%s checks=%d failed=%d missing=%d changed=%d unexpected=%d path=%q",
		input.Status,
		input.Checks,
		input.Failed,
		input.MissingFiles,
		input.ChangedFiles,
		input.UnexpectedFiles,
		input.Path,
	)
}
