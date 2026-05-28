package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	"github.com/watany-dev/gokui/internal/scan"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

const (
	reportStatusError       = "ERROR"
	reportDecisionRejected  = "REJECTED"
	reportDecisionFetchDone = "FETCHED"
)

type severityOverrideAudit = policypkg.SeverityOverrideAudit

const (
	inspectErrorCodeArgsInvalid         = "INSPECT_ARGS_INVALID"
	inspectErrorCodeSourceNotFound      = "INSPECT_SOURCE_NOT_FOUND"
	inspectErrorCodeSourceInvalid       = "INSPECT_SOURCE_INVALID"
	inspectErrorCodeGitHubRefNotPinned  = "INSPECT_GITHUB_REF_NOT_PINNED"
	inspectErrorCodeSourcePrepareFailed = "INSPECT_SOURCE_PREPARE_FAILED"
	inspectErrorCodeScanFailed          = "INSPECT_SCAN_FAILED"
	inspectErrorCodePolicyLoadFailed    = "INSPECT_POLICY_LOAD_FAILED"
	inspectErrorCodeUnknown             = "INSPECT_FAILED"
)

func BuildVersionString(cfg Config) string {
	version := cfg.Version
	if version == "" {
		version = "dev"
	}

	commit := cfg.Commit
	if commit == "" {
		commit = "none"
	}

	date := cfg.Date
	if date == "" {
		date = "unknown"
	}

	return fmt.Sprintf("%s (%s, %s)", version, commit, date)
}

func Run(args []string, stdout io.Writer, stderr io.Writer, cfg Config) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage())
		return exitcode.Error.Int()
	}

	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, BuildVersionString(cfg))
		return exitcode.OK.Int()
	}

	switch args[0] {
	case "fetch":
		return runFetch(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "vet":
		return runVet(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "lock":
		if len(args) >= 2 && args[1] == "verify" {
			return runLockVerify(args[2:], stdout, stderr)
		}
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
		return exitcode.Error.Int()
	}

	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
	return exitcode.Error.Int()
}

func usage() string {
	return strings.TrimSpace(`
gokui is pre-release software.

usage:
  gokui version
  gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json|sarif|compact]
  gokui inspect <local-dir|zip|tar|github-source> [--format human|json|sarif|compact|review-json]
  gokui vet <local-dir|zip|tar> [--profile strict|team|research] [--format human|json|sarif|compact|review-json]
  gokui install <source> --target codex --profile strict|team|research [--format human|json|sarif|compact] [--override RULE_ID ...]
  gokui update --dry-run [--target codex|custom:/path] [--format human|json|sarif|compact]
  gokui lock verify [path] [--format human|json|sarif|compact]`)
}

type vetDeps struct {
	LoadUserPolicy       func() (policypkg.Config, bool, error)
	LoadRepositoryPolicy func(string) (policypkg.Config, bool, error)
	RunInspect           func(args []string, stdout io.Writer, stderr io.Writer) int
}

func defaultVetDeps() vetDeps {
	return vetDeps{
		LoadUserPolicy:       policypkg.LoadUserPolicy,
		LoadRepositoryPolicy: policypkg.LoadRepositoryPolicy,
		RunInspect:           runInspect,
	}
}

func runVet(args []string, stdout io.Writer, stderr io.Writer) int {
	return runVetWithDeps(args, stdout, stderr, defaultVetDeps())
}

func runVetWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps vetDeps) int {
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	requestedReviewJSON := argsRequestFormat(args, "review-json")
	deps = normalizeVetDeps(deps)
	input, format, profile, profileSet, err := parseVetArgs(args)
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
			Note: "vet failed before source evaluation",
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

	sourceKind := detectSourceKind(input)
	if sourceKind == "github-source" {
		msg := "vet does not accept github sources; use local-dir, zip, or tar input"
		if emitInspectStructuredError(format, stdout, stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodeSourceInvalid,
			Message:       msg,
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet supports only local sources",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", msg, usage())
		return exitcode.Error.Int()
	}
	profile = policypkg.NormalizeProfile(profile).String()

	userPolicy, policyLoaded, policyErr := deps.LoadUserPolicy()
	if policyErr != nil {
		if emitInspectStructuredError(format, stdout, stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodePolicyLoadFailed,
			Message:       policyErr.Error(),
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet failed while loading policy configuration",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, policyErr.Error())
		return exitcode.Error.Int()
	}
	effectivePolicy := userPolicy
	effectivePolicyLoaded := policyLoaded
	if shouldApplyRepositoryPolicy(sourceKind) {
		repoPolicy, repoPolicyFound, repoPolicyErr := deps.LoadRepositoryPolicy(input)
		if repoPolicyErr != nil {
			if emitInspectStructuredError(format, stdout, stderr, inspectErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     inspectErrorCodePolicyLoadFailed,
				Message:       repoPolicyErr.Error(),
				Source: source{
					Input: input,
					Kind:  sourceKind,
				},
				Note: "vet failed while loading repository policy configuration",
			}) {
				return exitcode.Error.Int()
			}
			_, _ = fmt.Fprintln(stderr, repoPolicyErr.Error())
			return exitcode.Error.Int()
		}
		if repoPolicyFound {
			effectivePolicy = repoPolicy
			effectivePolicyLoaded = true
		}
	}
	if !profileSet && effectivePolicyLoaded && strings.TrimSpace(effectivePolicy.DefaultProfile) != "" {
		profile = effectivePolicy.DefaultProfile
	}
	profile = policypkg.NormalizeProfile(profile).String()
	if _, err := policypkg.ParseProfile(profile); err != nil {
		msg := fmt.Sprintf("unsupported profile: %s (supported: %s)", profile, policypkg.SupportedProfilesCSV())
		if emitInspectStructuredError(format, stdout, stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodeArgsInvalid,
			Message:       msg,
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet policy profile validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", msg, usage())
		return exitcode.Error.Int()
	}
	rejectSeverities, rejectSetErr := policypkg.EffectiveRejectSeverities(policypkg.NormalizeProfile(profile), effectivePolicyLoaded, effectivePolicy)
	if rejectSetErr != nil {
		if emitInspectStructuredError(format, stdout, stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodePolicyLoadFailed,
			Message:       rejectSetErr.Error(),
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet policy reject_severities configuration is invalid",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, rejectSetErr.Error())
		return exitcode.Error.Int()
	}
	rejectSet := rejectSeverities.Strings()

	var inspectStdout bytes.Buffer
	var inspectStderr bytes.Buffer
	inspectCode := deps.RunInspect([]string{input, "--format", "json"}, &inspectStdout, &inspectStderr)
	if inspectCode == 1 {
		errorReport := decodeInspectErrorPayload(inspectStdout.Bytes())
		if emitInspectStructuredError(format, stdout, stderr, errorReport) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, errorReport.Message)
		return exitcode.Error.Int()
	}

	report := buildVetReportFromInspectJSON(inspectStdout.Bytes(), input, sourceKind, profile, rejectSet)

	if format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "review-json" {
		out, _ := json.MarshalIndent(buildInspectReviewReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "sarif" {
		out, _ := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "compact" {
		summary := strings.Replace(buildInspectCompactSummary(report), "inspect ", "vet ", 1)
		_, _ = fmt.Fprintf(stdout, "%s\n", summary)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui vet report (pre-release)")
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

func normalizeVetDeps(deps vetDeps) vetDeps {
	if deps.LoadUserPolicy == nil {
		deps.LoadUserPolicy = policypkg.LoadUserPolicy
	}
	if deps.LoadRepositoryPolicy == nil {
		deps.LoadRepositoryPolicy = policypkg.LoadRepositoryPolicy
	}
	if deps.RunInspect == nil {
		deps.RunInspect = runInspect
	}
	return deps
}

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

func normalizeInspectDeps(deps inspectDeps) inspectDeps {
	if deps.PrepareEvaluationSource == nil {
		deps.PrepareEvaluationSource = preparePolicyEvaluationSource
	}
	if deps.PrepareInspectSource == nil {
		deps.PrepareInspectSource = prepareInspectSource
	}
	return deps
}
