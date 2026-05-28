package app

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
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
	requestedFormat, _ := requestedStructuredFormat(args, true)
	deps = normalizeInspectDeps(deps)
	input, format, err := parseInspectArgs(args)
	if err != nil {
		report := inspectArgsErrorReport("inspect", args, err)
		if code, ok := writeRequestedStructuredError(requestedFormat,
			func() int { return writeInspectJSONError(stdout, stderr, report) },
			func() int { return writeInspectSARIFError(stdout, stderr, report) },
		); ok {
			return code
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}
	structuredOutput := formatpkg.IsStructured(format)

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

	return writeInspectSuccessReport(format, report, stdout, stderr)
}
