package app

import (
	"io"

	reportpkg "github.com/watany-dev/gokui/internal/report"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func writeUpdateJSONError(stdout io.Writer, stderr io.Writer, report updateErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, updateFatalCodeUnknown)
	return writeJSONErrorReport(stdout, stderr, report, "update")
}

func writeUpdateSARIFError(stdout io.Writer, stderr io.Writer, report updateErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, updateFatalCodeUnknown)
	return writeSARIFErrorReport(stdout, stderr, buildUpdateSARIFErrorReport(report), "update")
}

func updateArgsErrorReport(args []string, err error) updateErrorReport {
	return updateErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        reportStatusError,
		ErrorCode:     updateFatalCodeArgsInvalid,
		Message:       err.Error(),
		Target:        extractUpdateTargetArg(args),
		Note:          "update failed before target resolution",
	}
}

func buildUpdateSARIFErrorReport(report updateErrorReport) reportpkg.SARIFDocument {
	return buildStructuredSARIFErrorReport(
		report.ErrorCode,
		report.RuleID,
		report.Message,
		report.SchemaVersion,
		report.Target,
		"update-target",
		report.Status,
		report.Note,
	)
}

func emitUpdateStructuredError(format string, stdout io.Writer, stderr io.Writer, report updateErrorReport) bool {
	return emitCommandStructuredError(format,
		func() int { return writeUpdateJSONError(stdout, stderr, report) },
		func() int { return writeUpdateSARIFError(stdout, stderr, report) },
	)
}

func buildUpdateSARIFReport(report updateReport) reportpkg.SARIFDocument {
	skills := make([]reportpkg.UpdateSARIFSkill, 0, len(report.Skills))
	for _, skill := range report.Skills {
		findings := make([]reportpkg.SARIFFinding, 0, len(skill.Findings))
		for _, finding := range skill.Findings {
			findings = append(findings, reportpkg.SARIFFinding{
				ID:       finding.ID,
				Severity: finding.Severity.String(),
				File:     finding.File,
				Line:     finding.Line,
				Summary:  finding.Summary,
			})
		}
		skills = append(skills, reportpkg.UpdateSARIFSkill{
			Name:      skill.Name,
			Status:    skill.Status,
			ErrorCode: skill.ErrorCode,
			RuleID:    skill.RuleID,
			Message:   skill.Message,
			Findings:  findings,
		})
	}
	return reportpkg.SARIFDocumentForUpdate(reportpkg.UpdateSARIFInput{
		SchemaVersion:            report.SchemaVersion,
		Target:                   report.Target,
		Note:                     report.Note,
		Summary:                  reportpkg.UpdateSARIFSummary{Changed: report.Summary.Changed, Rejected: report.Summary.Rejected, Errors: report.Summary.Errors},
		Skills:                   skills,
		StatusError:              reportStatusError,
		StatusRejected:           reportDecisionRejected,
		ErrorDecision:            reportStatusError,
		RejectedDecision:         reportDecisionRejected,
		ChangedDecision:          "CHANGED",
		PassDecision:             "PASS",
		SourceKind:               "update-target",
		StatusFallbackRuleID:     rulepkg.UpdateSkillStatus.ID,
		StatusFallbackSeverity:   "high",
		ExecutionFailureOnReject: true,
	})
}

func buildUpdateCompactSummary(report updateReport) string {
	return reportpkg.UpdateCompactSummary(reportpkg.UpdateCompactInput{
		Total:    report.Summary.Total,
		UpToDate: report.Summary.UpToDate,
		Changed:  report.Summary.Changed,
		Rejected: report.Summary.Rejected,
		Skipped:  report.Summary.Skipped,
		Errors:   report.Summary.Errors,
		Target:   report.Target,
	})
}
