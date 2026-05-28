package app

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
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
	ID       string `json:"id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Summary  string `json:"summary"`
}

func buildInspectCompactSummary(report inspectReport) string {
	severities := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		severities = append(severities, finding.Severity)
	}
	return reportpkg.InspectCompactSummary(report.Decision, report.Source.Kind, report.Source.Input, severities)
}

func buildInspectSARIFReport(report inspectReport) reportpkg.SARIFDocument {
	return buildFindingsSARIFReport(report.SchemaVersion, report.PreRelease, report.Source, report.Decision, report.Findings, report.Note)
}

func buildFindingsSARIFReport(schemaVersion string, preRelease bool, src source, decision string, findings []inspectFinding, note string) reportpkg.SARIFDocument {
	rules := make([]reportpkg.SARIFRule, 0)
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		rules = append(rules, reportpkg.SARIFRule{
			ID: finding.ID,
			ShortDescription: reportpkg.SARIFMessageContainer{
				Text: finding.Summary,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	results := make([]reportpkg.SARIFResult, 0, len(findings))
	for _, finding := range findings {
		result := reportpkg.SARIFResult{
			RuleID:  finding.ID,
			Level:   reportpkg.SARIFLevelForSeverity(finding.Severity),
			Message: reportpkg.SARIFMessageContainer{Text: finding.Summary},
		}
		location := reportpkg.SARIFLocation{
			PhysicalLocation: reportpkg.SARIFPhysicalLocation{
				ArtifactLocation: reportpkg.SARIFArtifactLocation{
					URI: finding.File,
				},
			},
		}
		if finding.Line > 0 {
			location.PhysicalLocation.Region = &reportpkg.SARIFRegion{StartLine: finding.Line}
		}
		if finding.File != "" {
			result.Locations = []reportpkg.SARIFLocation{location}
		}
		results = append(results, result)
	}

	return reportpkg.SARIFDocumentForRun(
		rules,
		results,
		decision != reportDecisionRejected,
		reportpkg.SARIFProperties{
			SchemaVersion: schemaVersion,
			PreRelease:    preRelease,
			SourceInput:   src.Input,
			SourceKind:    src.Kind,
			Decision:      decision,
			Note:          note,
		},
	)
}

func writeInspectJSONError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, inspectErrorCodeUnknown)
	return writeIndentedJSONLine(stdout, stderr, report, "failed to render inspect error report")
}

func writeInspectSARIFError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, inspectErrorCodeUnknown)
	return writeIndentedJSONLine(stdout, stderr, buildInspectSARIFErrorReport(report), "failed to render inspect SARIF error report")
}

func buildInspectSARIFErrorReport(report inspectErrorReport) reportpkg.SARIFDocument {
	return reportpkg.SARIFErrorDocument(structuredErrorRuleID(report.ErrorCode, report.RuleID), report.ErrorCode, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Source.Input,
		SourceKind:    report.Source.Kind,
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
	})
}

func emitInspectStructuredError(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) bool {
	if formatpkg.Format(format) == formatpkg.ReviewJSON {
		_ = writeInspectJSONError(stdout, stderr, report)
		return true
	}
	return emitStructuredError(format,
		func() { _ = writeInspectJSONError(stdout, stderr, report) },
		func() { _ = writeInspectSARIFError(stdout, stderr, report) },
	)
}

func emitInspectStructuredErrorCode(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	_ = emitInspectStructuredError(format, stdout, stderr, report)
	return exitcode.Error.Int()
}

func buildInspectReviewReport(report inspectReport) inspectReviewReport {
	reviewFindings := make([]inspectReviewFinding, 0, len(report.Findings))
	summary := inspectReviewSummary{}
	for _, finding := range report.Findings {
		reviewFindings = append(reviewFindings, inspectReviewFinding{
			ID:                 finding.ID,
			Severity:           finding.Severity,
			FileNeutralized:    neutralizeReviewText(finding.File),
			Line:               finding.Line,
			SummaryNeutralized: neutralizeReviewText(finding.Summary),
		})
		summary.Total++
		switch finding.Severity {
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
	return inspectReviewReport{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    report.PreRelease,
		Source: source{
			Input: neutralizeReviewText(report.Source.Input),
			Kind:  neutralizeReviewText(report.Source.Kind),
		},
		Decision:    report.Decision,
		Neutralized: true,
		Findings:    reviewFindings,
		Summary:     summary,
		Note:        report.Note,
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
			Severity: finding.Severity,
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
		sev := strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, reject := rejectSet[sev]; reject {
			return reportDecisionRejected
		}
	}
	return "PASS"
}

func decodeInspectErrorPayload(raw []byte) inspectErrorReport {
	out := inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        reportStatusError,
		ErrorCode:     inspectErrorCodeUnknown,
		Message:       "failed to process inspect error report",
		Source: source{
			Input: "",
			Kind:  "local-dir",
		},
		Note: "vet failed while decoding inspect error report",
	}
	if !utf8.Valid(raw) {
		out.Message = "inspect error payload must be valid UTF-8"
		out.Note = "vet failed while decoding inspect error report (non-UTF-8 payload)"
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		message := strings.TrimSpace(string(raw))
		if message == "" {
			return out
		}
		out.Message = message
		return out
	}
	if strings.TrimSpace(out.Message) == "" {
		out.Message = "inspect failed"
	}
	return out
}

func buildVetReportFromInspectJSON(raw []byte, input string, sourceKind string, profile string, rejectSet map[string]struct{}) inspectReport {
	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: reportDecisionRejected,
		Findings: []inspectFinding{},
		Note:     "vet failed to parse inspect report; fail-closed rejection applied",
	}
	if !utf8.Valid(raw) {
		report.Note = "vet rejected non-UTF-8 inspect report; fail-closed rejection applied"
		report.Note = fmt.Sprintf("%s (vet profile=%s)", report.Note, profile)
		return report
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		report.Note = fmt.Sprintf("vet failed to parse inspect report (%v); fail-closed rejection applied", err)
		report.Note = fmt.Sprintf("%s (vet profile=%s)", report.Note, profile)
		return report
	}
	report.Decision = decisionForInspectFindings(report.Findings, rejectSet)
	report.Note = fmt.Sprintf("%s (vet profile=%s)", report.Note, profile)
	return report
}
