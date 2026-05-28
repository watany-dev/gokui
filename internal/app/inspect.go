package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	"github.com/watany-dev/gokui/internal/scan"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type inspectDeps struct {
	PrepareEvaluationSource func(input string, sourceKind string) (string, func(), error)
	PrepareInspectSource    func(input string, sourceKind string) (string, func(), error)
}

func defaultInspectDeps() inspectDeps {
	return inspectDeps{
		PrepareEvaluationSource: preparePolicyEvaluationSource,
		PrepareInspectSource:    prepareInspectSource,
	}
}

func runInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	return runInspectWithDeps(args, stdout, stderr, defaultInspectDeps())
}

func runInspectWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps inspectDeps) int {
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	requestedReviewJSON := argsRequestFormat(args, "review-json")
	deps = normalizeInspectDeps(deps)
	input, format, err := parseInspectArgs(args)
	if err != nil {
		sourceArg := extractInspectSourceArg(args)
		report := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodeArgsInvalid,
			Message:       err.Error(),
			Source: source{
				Input: sourceArg,
				Kind:  detectSourceKind(sourceArg),
			},
			Note: "inspect failed before source evaluation",
		}
		if requestedJSON {
			return writeInspectJSONError(stdout, stderr, report)
		}
		if requestedSARIF {
			return writeInspectSARIFError(stdout, stderr, report)
		}
		if requestedReviewJSON {
			return writeInspectJSONError(stdout, stderr, report)
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}
	structuredOutput := format == "json" || format == "sarif" || format == "review-json"

	sourceKind := detectSourceKind(input)

	if sourceKind != "github-source" {
		if _, statErr := os.Stat(input); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				if structuredOutput {
					return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
						SchemaVersion: reportSchemaVersion,
						Status:        reportStatusError,
						ErrorCode:     inspectErrorCodeSourceNotFound,
						Message:       fmt.Sprintf("inspect source not found: %s", input),
						Source: source{
							Input: input,
							Kind:  sourceKind,
						},
						Note: "inspect source must exist before validation",
					})
				}
				_, _ = fmt.Fprintf(stderr, "inspect source not found: %s\n", input)
				return exitcode.Error.Int()
			}
			accessErr := fmt.Sprintf("failed to access inspect source: %v", statErr)
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeSourcePrepareFailed,
					Message:       accessErr,
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect source access check failed",
				})
			}
			_, _ = fmt.Fprintln(stderr, accessErr)
			return exitcode.Error.Int()
		}
	}

	var findings []inspectFinding
	decision := "PASS"
	note := "pre-release inspect includes structural and markdown checks"
	if sourceKind == "github-source" {
		spec, parseErr := srcpkg.ParseGitHubSource(input)
		if parseErr != nil {
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeSourceInvalid,
					Message:       fmt.Sprintf("invalid github source: %v", parseErr),
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect github source syntax validation failed",
				})
			}
			_, _ = fmt.Fprintf(stderr, "invalid github source: %v\n", parseErr)
			return exitcode.Error.Int()
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			msg := "inspect github source requires a commit-pinned ref (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)"
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeGitHubRefNotPinned,
					Message:       msg,
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect github source ref must be commit-pinned",
				})
			}
			_, _ = fmt.Fprintln(stderr, msg)
			return exitcode.Error.Int()
		}
		skillRoot, cleanup, prepErr := deps.PrepareEvaluationSource(input, sourceKind)
		if cleanup != nil {
			defer cleanup()
		}
		if prepErr != nil {
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeSourcePrepareFailed,
					Message:       prepErr.Error(),
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect source preparation failed",
				})
			}
			_, _ = fmt.Fprintln(stderr, prepErr.Error())
			return exitcode.Error.Int()
		}
		scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
		if scanErr != nil {
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeScanFailed,
					Message:       scanErr.Error(),
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect scanning failed",
				})
			}
			_, _ = fmt.Fprintln(stderr, scanErr.Error())
			return exitcode.Error.Int()
		}
		findings, decision = toInspectFindings(scanFindings)
		note = "pre-release inspect includes structural and markdown checks (github commit-pinned source)"
	} else {
		skillRoot, cleanup, validateErr := deps.PrepareInspectSource(input, sourceKind)
		if cleanup != nil {
			defer cleanup()
		}
		if validateErr != nil {
			if structuredOutput {
				errorCode := inspectErrorCodeSourcePrepareFailed
				if isInspectSourceNotFoundError(validateErr) {
					errorCode = inspectErrorCodeSourceNotFound
				}
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     errorCode,
					Message:       validateErr.Error(),
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect source preparation failed",
				})
			}
			_, _ = fmt.Fprintln(stderr, validateErr.Error())
			return exitcode.Error.Int()
		}
		scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
		if scanErr != nil {
			if structuredOutput {
				return emitInspectStructuredErrorCode(format, stdout, stderr, inspectErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     inspectErrorCodeScanFailed,
					Message:       scanErr.Error(),
					Source: source{
						Input: input,
						Kind:  sourceKind,
					},
					Note: "inspect scanning failed",
				})
			}
			_, _ = fmt.Fprintln(stderr, scanErr.Error())
			return exitcode.Error.Int()
		}
		findings, decision = toInspectFindings(scanFindings)
	}

	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: decision,
		Findings: findings,
		Note:     note,
	}

	if format == "json" {
		out, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "review-json" {
		out, marshalErr := json.MarshalIndent(buildInspectReviewReport(report), "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect review report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "sarif" {
		out, marshalErr := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect SARIF report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildInspectCompactSummary(report))
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui inspect report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
	}
	if report.Decision == reportDecisionRejected {
		return exitcode.Rejected.Int()
	}
	return exitcode.OK.Int()
}
