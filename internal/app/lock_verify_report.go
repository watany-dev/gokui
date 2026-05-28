package app

import (
	"io"

	reportpkg "github.com/watany-dev/gokui/internal/report"
)

func buildLockVerifyCompactSummary(report lockVerifyReport) string {
	failed := 0
	for _, check := range report.Checks {
		if !check.OK {
			failed++
		}
	}
	return reportpkg.LockVerifyCompactSummary(reportpkg.LockVerifyCompactInput{
		Status:          report.Status,
		Checks:          len(report.Checks),
		Failed:          failed,
		MissingFiles:    len(report.Drift.MissingFiles),
		ChangedFiles:    len(report.Drift.ChangedFiles),
		UnexpectedFiles: len(report.Drift.UnexpectedFiles),
		Path:            report.SkillPath,
	})
}

func buildLockVerifySARIFReport(report lockVerifyReport) reportpkg.SARIFDocument {
	checks := make([]reportpkg.LockVerifySARIFCheck, 0, len(report.Checks))
	for _, check := range report.Checks {
		checks = append(checks, reportpkg.LockVerifySARIFCheck{
			Code:   check.Code,
			Name:   check.Name,
			OK:     check.OK,
			Detail: check.Detail,
		})
	}
	return reportpkg.SARIFDocumentForLockVerify(reportpkg.LockVerifySARIFInput{
		Status:         report.Status,
		VerifiedStatus: "VERIFIED",
		FileDigestCode: lockVerifyCodeFileDigests,
		Checks:         checks,
		Drift: reportpkg.LockVerifySARIFDrift{
			MissingFiles:    report.Drift.MissingFiles,
			ChangedFiles:    report.Drift.ChangedFiles,
			UnexpectedFiles: report.Drift.UnexpectedFiles,
		},
		Properties: reportpkg.SARIFProperties{
			SchemaVersion: report.SchemaVersion,
			PreRelease:    true,
			SourceInput:   report.SkillPath,
			SourceKind:    "installed-skill",
			Note:          report.Note,
		},
	})
}

func writeLockVerifyJSONError(stdout io.Writer, stderr io.Writer, report lockVerifyErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, lockVerifyErrorCodeUnknown)
	return writeJSONErrorReport(stdout, stderr, report, "lock verify")
}

func writeLockVerifySARIFError(stdout io.Writer, stderr io.Writer, report lockVerifyErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, lockVerifyErrorCodeUnknown)
	return writeSARIFErrorReport(stdout, stderr, buildLockVerifySARIFErrorReport(report), "lock verify")
}

func lockVerifyArgsErrorReport(args []string, err error) lockVerifyErrorReport {
	return lockVerifyErrorReport{
		SchemaVersion: reportSchemaVersion,
		SkillPath:     extractLockVerifyPathArg(args),
		Status:        reportStatusError,
		ErrorCode:     lockVerifyErrorCodeArgsInvalid,
		Message:       err.Error(),
		Note:          "lock verify failed before path validation",
	}
}

func emitLockVerifyStructuredError(format string, stdout io.Writer, stderr io.Writer, report lockVerifyErrorReport) bool {
	return emitCommandStructuredError(format,
		func() int { return writeLockVerifyJSONError(stdout, stderr, report) },
		func() int { return writeLockVerifySARIFError(stdout, stderr, report) },
	)
}

func buildLockVerifySARIFErrorReport(report lockVerifyErrorReport) reportpkg.SARIFDocument {
	return buildStructuredSARIFErrorReport(report.ErrorCode, report.RuleID, report.Message,
		structuredErrorSARIFProperties(report.SchemaVersion, report.SkillPath, "installed-skill", report.Status, report.Note, report.ErrorCode),
	)
}
