package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	"github.com/watany-dev/gokui/internal/scan"
)

type inspectReport struct {
	SchemaVersion string           `json:"schema_version"`
	PreRelease    bool             `json:"pre_release"`
	Source        source           `json:"source"`
	Decision      string           `json:"decision"`
	Findings      []inspectFinding `json:"findings"`
	Note          string           `json:"note"`
}

type inspectReviewReport struct {
	SchemaVersion string                 `json:"schema_version"`
	PreRelease    bool                   `json:"pre_release"`
	Source        source                 `json:"source"`
	Decision      string                 `json:"decision"`
	Neutralized   bool                   `json:"neutralized"`
	Findings      []inspectReviewFinding `json:"findings"`
	Summary       inspectReviewSummary   `json:"summary"`
	Note          string                 `json:"note"`
}

type inspectReviewFinding struct {
	ID                 string `json:"id"`
	Severity           string `json:"severity"`
	FileNeutralized    string `json:"file_neutralized"`
	Line               int    `json:"line"`
	SummaryNeutralized string `json:"summary_neutralized"`
}

type inspectReviewSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type inspectErrorReport struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code"`
	RuleID        string `json:"rule_id,omitempty"`
	Message       string `json:"message"`
	Source        source `json:"source"`
	Note          string `json:"note"`
}

type source struct {
	Input string `json:"input"`
	Kind  string `json:"kind"`
}

type inspectFinding struct {
	ID       string             `json:"id"`
	Severity policypkg.Severity `json:"severity"`
	File     string             `json:"file"`
	Line     int                `json:"line"`
	Summary  string             `json:"summary"`
}

func buildInspectCompactSummary(report inspectReport) string {
	severities := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		severities = append(severities, finding.Severity.String())
	}
	return reportpkg.InspectCompactSummary(report.Decision, report.Source.Kind, report.Source.Input, severities)
}

func buildInspectSARIFReport(report inspectReport) reportpkg.SARIFDocument {
	return buildFindingsSARIFReport(report.SchemaVersion, report.PreRelease, report.Source, report.Decision, report.Findings, report.Note)
}

func buildFindingsSARIFReport(schemaVersion string, preRelease bool, src source, decision string, findings []inspectFinding, note string) reportpkg.SARIFDocument {
	sarifFindings := make([]reportpkg.SARIFFinding, 0, len(findings))
	for _, finding := range findings {
		sarifFindings = append(sarifFindings, reportpkg.SARIFFinding{
			ID:       finding.ID,
			Severity: finding.Severity.String(),
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
	}
	return reportpkg.SARIFDocumentForFindingsInput(reportpkg.FindingsSARIFInput{
		SchemaVersion: schemaVersion,
		PreRelease:    preRelease,
		SourceInput:   src.Input,
		SourceKind:    src.Kind,
		Decision:      decision,
		Rejected:      decision == reportDecisionRejected,
		Note:          note,
		Findings:      sarifFindings,
	})
}

func inspectArgsErrorReport(command string, args []string, err error) inspectErrorReport {
	sourceArg := extractInspectSourceArg(args)
	return inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        reportStatusError,
		ErrorCode:     inspectErrorCodeArgsInvalid,
		Message:       err.Error(),
		Source: source{
			Input: sourceArg,
			Kind:  detectSourceKind(sourceArg),
		},
		Note: fmt.Sprintf("%s failed before source evaluation", command),
	}
}

func writeInspectJSONError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, inspectErrorCodeUnknown)
	return writeJSONErrorReport(stdout, stderr, report, "inspect")
}

func writeInspectSARIFError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, inspectErrorCodeUnknown)
	return writeSARIFErrorReport(stdout, stderr, buildInspectSARIFErrorReport(report), "inspect")
}

func buildInspectSARIFErrorReport(report inspectErrorReport) reportpkg.SARIFDocument {
	return buildStructuredSARIFErrorReport(
		report.ErrorCode,
		report.RuleID,
		report.Message,
		report.SchemaVersion,
		report.Source.Input,
		report.Source.Kind,
		report.Status,
		report.Note,
	)
}

func emitInspectStructuredError(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) bool {
	outputFormat := formatpkg.Format(format)
	if outputFormat == formatpkg.ReviewJSON {
		_ = writeInspectJSONError(stdout, stderr, report)
		return true
	}
	return emitStructuredError(outputFormat,
		func() { _ = writeInspectJSONError(stdout, stderr, report) },
		func() { _ = writeInspectSARIFError(stdout, stderr, report) },
	)
}

func emitInspectStructuredErrorCode(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	_ = emitInspectStructuredError(format, stdout, stderr, report)
	return exitcode.Error.Int()
}

func buildInspectReviewReport(report inspectReport) inspectReviewReport {
	inputs := make([]reportpkg.ReviewFindingInput, 0, len(report.Findings))
	for _, finding := range report.Findings {
		inputs = append(inputs, reportpkg.ReviewFindingInput{
			ID:       finding.ID,
			Severity: finding.Severity.String(),
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
	}
	reviewFindings, summary := reportpkg.ReviewFindings(inputs)
	return inspectReviewReport{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    report.PreRelease,
		Source: source{
			Input: neutralizeReviewText(report.Source.Input),
			Kind:  neutralizeReviewText(report.Source.Kind),
		},
		Decision:    report.Decision,
		Neutralized: true,
		Findings:    inspectReviewFindingsFromReport(reviewFindings),
		Summary:     inspectReviewSummaryFromReport(summary),
		Note:        report.Note,
	}
}

func inspectReviewFindingsFromReport(findings []reportpkg.ReviewFinding) []inspectReviewFinding {
	out := make([]inspectReviewFinding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, inspectReviewFinding{
			ID:                 finding.ID,
			Severity:           finding.Severity,
			FileNeutralized:    finding.FileNeutralized,
			Line:               finding.Line,
			SummaryNeutralized: finding.SummaryNeutralized,
		})
	}
	return out
}

func inspectReviewSummaryFromReport(summary reportpkg.ReviewSummary) inspectReviewSummary {
	return inspectReviewSummary{
		Total:    summary.Total,
		Critical: summary.Critical,
		High:     summary.High,
		Medium:   summary.Medium,
		Low:      summary.Low,
	}
}

func neutralizeReviewText(text string) string {
	return reportpkg.NeutralizeReviewText(text)
}

func toInspectFindings(scanFindings []scan.Finding) ([]inspectFinding, string) {
	findings := make([]inspectFinding, 0, len(scanFindings))
	decision := "PASS"
	for _, finding := range scanFindings {
		findings = append(findings, inspectFinding{
			ID:       finding.ID,
			Severity: policypkg.Severity(finding.Severity),
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
		if scan.IsRejectable(finding) {
			decision = reportDecisionRejected
		}
	}
	return findings, decision
}

func decisionForInspectFindings(findings []inspectFinding, rejectSet map[string]struct{}) string {
	for _, finding := range findings {
		sev := strings.ToLower(strings.TrimSpace(finding.Severity.String()))
		if _, reject := rejectSet[sev]; reject {
			return reportDecisionRejected
		}
	}
	return "PASS"
}
