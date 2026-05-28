package app

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
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
	return buildStructuredSARIFErrorReport(report.ErrorCode, report.RuleID, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Target,
		SourceKind:    "update-target",
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
	})
}

func emitUpdateStructuredError(format string, stdout io.Writer, stderr io.Writer, report updateErrorReport) bool {
	return emitCommandStructuredError(format,
		func() int { return writeUpdateJSONError(stdout, stderr, report) },
		func() int { return writeUpdateSARIFError(stdout, stderr, report) },
	)
}

func buildUpdateSARIFReport(report updateReport) reportpkg.SARIFDocument {
	decision := "PASS"
	if report.Summary.Errors > 0 {
		decision = reportStatusError
	} else if report.Summary.Rejected > 0 {
		decision = reportDecisionRejected
	} else if report.Summary.Changed > 0 {
		decision = "CHANGED"
	}

	findings := make([]inspectFinding, 0, 64)
	for _, skill := range report.Skills {
		if len(skill.Findings) > 0 {
			for _, finding := range skill.Findings {
				filePath := finding.File
				if filePath != "" {
					filePath = filepath.ToSlash(filepath.Join(skill.Name, filePath))
				}
				summary := finding.Summary
				if strings.TrimSpace(summary) == "" {
					summary = fmt.Sprintf("%s finding in %s", finding.ID, skill.Name)
				}
				findings = append(findings, inspectFinding{
					ID:       finding.ID,
					Severity: finding.Severity,
					File:     filePath,
					Line:     finding.Line,
					Summary:  summary,
				})
			}
			continue
		}
		if skill.Status != reportStatusError && skill.Status != reportDecisionRejected {
			continue
		}
		ruleID := skill.RuleID
		if ruleID == "" {
			ruleID = skill.ErrorCode
		}
		if ruleID == "" {
			ruleID = rulepkg.UpdateSkillStatus.ID
		}
		summary := skill.Message
		if strings.TrimSpace(summary) == "" {
			summary = fmt.Sprintf("%s: %s", skill.Status, skill.Name)
		}
		findings = append(findings, inspectFinding{
			ID:       ruleID,
			Severity: policypkg.SeverityHigh,
			File:     filepath.ToSlash(skill.Name),
			Line:     1,
			Summary:  summary,
		})
	}

	sarif := buildFindingsSARIFReport(
		report.SchemaVersion,
		true,
		source{
			Input: report.Target,
			Kind:  "update-target",
		},
		decision,
		findings,
		report.Note,
	)
	if len(sarif.Runs) > 0 {
		sarif.Runs[0].Invocations = []reportpkg.SARIFInvocation{
			{ExecutionSuccessful: report.Summary.Errors == 0 && report.Summary.Rejected == 0},
		}
	}
	return sarif
}

func buildUpdateCompactSummary(report updateReport) string {
	return fmt.Sprintf(
		"update total=%d up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d target=%q",
		report.Summary.Total,
		report.Summary.UpToDate,
		report.Summary.Changed,
		report.Summary.Rejected,
		report.Summary.Skipped,
		report.Summary.Errors,
		report.Target,
	)
}
