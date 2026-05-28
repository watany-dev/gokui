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
		severities = append(severities, finding.Severity.String())
	}
	return reportpkg.InstallCompactSummary(reportpkg.InstallCompactInput{
		Decision:      report.Decision,
		Severities:    severities,
		Overrides:     len(report.SeverityOverrides),
		Installed:     report.Installed,
		PolicyProfile: report.PolicyProfile,
		Target:        target,
		SourceKind:    report.Source.Kind,
		SourceInput:   report.Source.Input,
		ErrorCode:     report.ErrorCode,
	})
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
	return buildStructuredSARIFErrorReport(report.ErrorCode, report.RuleID, report.Message,
		structuredErrorSARIFProperties(
			report.SchemaVersion,
			report.Source.Input,
			report.Source.Kind,
			report.Status,
			fmt.Sprintf("target=%s profile=%s; %s", report.Target, report.PolicyProfile, report.Note),
			report.ErrorCode,
		),
	)
}

func emitInstallStructuredError(format string, stdout io.Writer, stderr io.Writer, report installErrorReport) bool {
	return emitCommandStructuredError(format,
		func() int { return writeInstallJSONError(stdout, stderr, report) },
		func() int { return writeInstallSARIFError(stdout, stderr, report) },
	)
}
