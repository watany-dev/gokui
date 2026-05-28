package app

import (
	"fmt"
	"io"
	"sort"
	"strings"

	reportpkg "github.com/watany-dev/gokui/internal/report"
)

func buildLockVerifyCompactSummary(report lockVerifyReport) string {
	failed := 0
	for _, check := range report.Checks {
		if !check.OK {
			failed++
		}
	}
	return fmt.Sprintf(
		"lock_verify status=%s checks=%d failed=%d missing=%d changed=%d unexpected=%d path=%q",
		report.Status,
		len(report.Checks),
		failed,
		len(report.Drift.MissingFiles),
		len(report.Drift.ChangedFiles),
		len(report.Drift.UnexpectedFiles),
		report.SkillPath,
	)
}

func buildLockVerifySARIFReport(report lockVerifyReport) reportpkg.SARIFDocument {
	decision := "PASS"
	if report.Status != "VERIFIED" {
		decision = "DRIFTED"
	}

	rules := make([]reportpkg.SARIFRule, 0, len(report.Checks))
	for _, check := range report.Checks {
		rules = append(rules, reportpkg.SARIFRuleForFinding(check.Code, fmt.Sprintf("lock verify check: %s", check.Name)))
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	results := make([]reportpkg.SARIFResult, 0, 32)
	for _, check := range report.Checks {
		if check.OK {
			continue
		}
		results = append(results, reportpkg.SARIFResultForFinding(check.Code, "error", check.Detail, nil))
		if check.Code != lockVerifyCodeFileDigests {
			continue
		}
		for _, path := range report.Drift.MissingFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "missing file listed in lock"))
		}
		for _, path := range report.Drift.ChangedFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "changed file hash or size"))
		}
		for _, path := range report.Drift.UnexpectedFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "unexpected file not listed in lock"))
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		uriI := ""
		if len(results[i].Locations) > 0 {
			uriI = results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		uriJ := ""
		if len(results[j].Locations) > 0 {
			uriJ = results[j].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		if uriI != uriJ {
			return uriI < uriJ
		}
		return results[i].Message.Text < results[j].Message.Text
	})

	return reportpkg.SARIFDocumentForRun(
		rules,
		results,
		report.Status == "VERIFIED",
		reportpkg.SARIFProperties{
			SchemaVersion: report.SchemaVersion,
			PreRelease:    true,
			SourceInput:   report.SkillPath,
			SourceKind:    "installed-skill",
			Decision:      decision,
			Note:          report.Note,
		},
	)
}

func lockVerifyDriftSARIFResult(ruleID string, path string, reason string) reportpkg.SARIFResult {
	message := fmt.Sprintf("%s: %s", reason, path)
	if strings.TrimSpace(path) == "" {
		return reportpkg.SARIFResultForFinding(ruleID, "error", message, nil)
	}
	return reportpkg.SARIFResultForFinding(
		ruleID,
		"error",
		message,
		[]reportpkg.SARIFLocation{reportpkg.SARIFLocationForFile(path, 0)},
	)
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
	return buildStructuredSARIFErrorReport(report.ErrorCode, report.RuleID, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.SkillPath,
		SourceKind:    "installed-skill",
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
	})
}
