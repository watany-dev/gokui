package app

import (
	"fmt"
	"io"

	reportpkg "github.com/watany-dev/gokui/internal/report"
)

func buildInstallSARIFReport(report installReport, target string) reportpkg.SARIFDocument {
	return buildFindingsSARIFReport(
		report.SchemaVersion,
		true,
		report.Source,
		report.Decision,
		report.Findings,
		fmt.Sprintf(
			"install target=%s profile=%s installed=%t path=%s error_code=%s overrides=%d; %s",
			target,
			report.PolicyProfile,
			report.Installed,
			report.InstalledPath,
			report.ErrorCode,
			len(report.SeverityOverrides),
			report.Note,
		),
	)
}

func buildInstallCompactSummary(report installReport, target string) string {
	severities := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		severities = append(severities, finding.Severity)
	}
	counts := reportpkg.CountSeverities(severities)
	return fmt.Sprintf(
		"install decision=%s findings=%d critical=%d high=%d medium=%d low=%d overrides=%d installed=%t profile=%s target=%q source_kind=%s source=%q error_code=%s",
		report.Decision,
		len(report.Findings),
		counts.Critical,
		counts.High,
		counts.Medium,
		counts.Low,
		len(report.SeverityOverrides),
		report.Installed,
		report.PolicyProfile,
		target,
		report.Source.Kind,
		report.Source.Input,
		report.ErrorCode,
	)
}

func writeInstallJSONError(stdout io.Writer, stderr io.Writer, report installErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, installErrorCodeUnknown)
	return writeJSONErrorReport(stdout, stderr, report, "install")
}

func writeInstallSARIFError(stdout io.Writer, stderr io.Writer, report installErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, installErrorCodeUnknown)
	return writeSARIFErrorReport(stdout, stderr, buildInstallSARIFErrorReport(report), "install")
}

func installArgsErrorReport(args []string, err error) installErrorReport {
	sourceArg := extractInstallSourceArg(args)
	return installErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        reportStatusError,
		ErrorCode:     installErrorCodeArgsInvalid,
		Message:       err.Error(),
		Source: source{
			Input: sourceArg,
			Kind:  detectSourceKind(sourceArg),
		},
		Target:        extractInstallTargetArg(args),
		PolicyProfile: extractInstallProfileArg(args),
		Note:          "install failed before source evaluation",
	}
}

func buildInstallSARIFErrorReport(report installErrorReport) reportpkg.SARIFDocument {
	return reportpkg.SARIFErrorDocument(structuredErrorRuleID(report.ErrorCode, report.RuleID), report.ErrorCode, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Source.Input,
		SourceKind:    report.Source.Kind,
		Decision:      report.Status,
		Note: fmt.Sprintf(
			"target=%s profile=%s; %s; error_code=%s",
			report.Target,
			report.PolicyProfile,
			report.Note,
			report.ErrorCode,
		),
	})
}

func emitInstallStructuredError(format string, stdout io.Writer, stderr io.Writer, report installErrorReport) bool {
	return emitCommandStructuredError(format,
		func() int { return writeInstallJSONError(stdout, stderr, report) },
		func() int { return writeInstallSARIFError(stdout, stderr, report) },
	)
}
