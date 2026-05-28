package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	"github.com/watany-dev/gokui/internal/materialize"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/scan"
	skillpkg "github.com/watany-dev/gokui/internal/skill"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type Config struct {
	Version string
	Commit  string
	Date    string
}

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

type severityOverrideAudit = policypkg.SeverityOverrideAudit

var (
	errorCodePattern               = regexp.MustCompile(`^[A-Z0-9_]+$`)
	maxSkillFrontmatterBytes int64 = 1_000_000
	errInspectSourceNotFound       = skillpkg.ErrInspectSourceNotFound
)

const ruleSkillFrontmatterTooLarge = skillpkg.RuleFrontmatterTooLarge
const (
	ruleInspectSourceSymlink          = skillpkg.RuleInspectSourceSymlink
	ruleSkillFrontmatterSymlink       = skillpkg.RuleFrontmatterSymlink
	ruleSkillFrontmatterSpecialFile   = skillpkg.RuleFrontmatterSpecialFile
	ruleSkillFrontmatterInvalidUTF8   = skillpkg.RuleFrontmatterInvalidUTF8
	ruleSkillFrontmatterSourceChanged = skillpkg.RuleFrontmatterSourceChanged
)

const (
	descriptionToolInjectionRuleID      = skillpkg.RuleDescriptionToolInjection
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
	requestedJSON := inspectArgsRequestJSON(args)
	requestedSARIF := inspectArgsRequestSARIF(args)
	requestedReviewJSON := inspectArgsRequestReviewJSON(args)
	deps = normalizeVetDeps(deps)
	input, format, profile, profileSet, err := parseVetArgs(args)
	if err != nil {
		sourceArg := extractInspectSourceArg(args)
		report := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			Status:        "ERROR",
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
			Status:        "ERROR",
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
				Status:        "ERROR",
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
			Status:        "ERROR",
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
			Status:        "ERROR",
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
		if report.Decision == "REJECTED" {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "review-json" {
		out, _ := json.MarshalIndent(buildInspectReviewReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == "REJECTED" {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "sarif" {
		out, _ := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == "REJECTED" {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "compact" {
		summary := strings.Replace(buildInspectCompactSummary(report), "inspect ", "vet ", 1)
		_, _ = fmt.Fprintf(stdout, "%s\n", summary)
		if report.Decision == "REJECTED" {
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
	if report.Decision == "REJECTED" {
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

func buildVetReportFromInspectJSON(raw []byte, input string, sourceKind string, profile string, rejectSet map[string]struct{}) inspectReport {
	report := inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: "REJECTED",
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
	requestedJSON := inspectArgsRequestJSON(args)
	requestedSARIF := inspectArgsRequestSARIF(args)
	requestedReviewJSON := inspectArgsRequestReviewJSON(args)
	deps = normalizeInspectDeps(deps)
	input, format, err := parseInspectArgs(args)
	if err != nil {
		sourceArg := extractInspectSourceArg(args)
		report := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
						Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
					Status:        "ERROR",
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
		if report.Decision == "REJECTED" {
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
		if report.Decision == "REJECTED" {
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
		if report.Decision == "REJECTED" {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}
	if format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildInspectCompactSummary(report))
		if report.Decision == "REJECTED" {
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
	if report.Decision == "REJECTED" {
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
			decision = "REJECTED"
		}
	}
	return findings, decision
}

func prepareInspectSource(input string, sourceKind string) (skillRoot string, cleanup func(), err error) {
	switch sourceKind {
	case "local-dir":
		if validateErr := validateLocalDirInspectSource(input); validateErr != nil {
			return "", nil, validateErr
		}
		return input, nil, nil
	case "zip", "tar":
		return prepareArchiveInspectSource(input, sourceKind)
	default:
		return "", nil, fmt.Errorf("unsupported inspect source kind: %s", sourceKind)
	}
}

func prepareArchiveInspectSource(input string, sourceKind string) (string, func(), error) {
	tempRoot, err := os.MkdirTemp("", "gokui-inspect-archive-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create inspect quarantine: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempRoot)
	}

	extractDir := filepath.Join(tempRoot, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to prepare inspect extraction directory: %w", err)
	}

	limits := materialize.Limits{
		MaxFiles:      1000,
		MaxTotalBytes: 50 * 1024 * 1024,
		MaxFileBytes:  10 * 1024 * 1024,
	}
	if err := materialize.ExtractArchive(input, sourceKind, extractDir, limits); err != nil {
		cleanup()
		return "", nil, err
	}

	skillRoot, err := materialize.DetectSkillRoot(extractDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	if err := validateLocalDirInspectSource(skillRoot); err != nil {
		cleanup()
		return "", nil, err
	}

	return skillRoot, cleanup, nil
}

func parseInspectArgs(args []string) (input string, format string, err error) {
	format = "human"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("missing value for --format")
			}
			format = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", fmt.Errorf("unknown inspect option: %s", arg)
		}
		if input != "" {
			return "", "", fmt.Errorf("inspect accepts exactly one source")
		}
		input = arg
	}

	if input == "" {
		return "", "", fmt.Errorf("inspect source is required")
	}
	if format != "human" && format != "json" && format != "sarif" && format != "compact" && format != "review-json" {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}

func parseVetArgs(args []string) (input string, format string, profile string, profileSet bool, err error) {
	format = "human"
	profile = policypkg.ProfileStrict.String()
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			if i+1 >= len(args) {
				return "", "", "", false, fmt.Errorf("missing value for --format")
			}
			format = args[i+1]
			i++
			continue
		}
		if arg == "--profile" {
			if i+1 >= len(args) {
				return "", "", "", false, fmt.Errorf("missing value for --profile")
			}
			profile = args[i+1]
			profileSet = true
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
			continue
		}
		if strings.HasPrefix(arg, "--profile=") {
			profile = strings.TrimPrefix(arg, "--profile=")
			profileSet = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			return "", "", "", false, fmt.Errorf("unknown vet option: %s", arg)
		}
		if input != "" {
			return "", "", "", false, fmt.Errorf("vet accepts exactly one source")
		}
		input = arg
	}

	if input == "" {
		return "", "", "", false, fmt.Errorf("vet source is required")
	}
	if format != "human" && format != "json" && format != "sarif" && format != "compact" && format != "review-json" {
		return "", "", "", false, fmt.Errorf("unsupported vet format: %s", format)
	}
	return input, format, profile, profileSet, nil
}

func decisionForInspectFindings(findings []inspectFinding, rejectSet map[string]struct{}) string {
	for _, finding := range findings {
		sev := strings.ToLower(strings.TrimSpace(finding.Severity))
		if _, reject := rejectSet[sev]; reject {
			return "REJECTED"
		}
	}
	return "PASS"
}

func decodeInspectErrorPayload(raw []byte) inspectErrorReport {
	out := inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
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

func buildInspectCompactSummary(report inspectReport) string {
	severities := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		severities = append(severities, finding.Severity)
	}
	return reportpkg.InspectCompactSummary(report.Decision, report.Source.Kind, report.Source.Input, severities)
}

func buildInspectSARIFReport(report inspectReport) reportpkg.SARIFDocument {
	rules := make([]reportpkg.SARIFRule, 0)
	seen := make(map[string]struct{}, len(report.Findings))
	for _, finding := range report.Findings {
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

	results := make([]reportpkg.SARIFResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		result := reportpkg.SARIFResult{
			RuleID:  finding.ID,
			Level:   inspectSeverityToSARIFLevel(finding.Severity),
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

	return reportpkg.SARIFDocument{
		Version: reportpkg.SARIFVersion,
		Schema:  reportpkg.SARIFSchema,
		Runs: []reportpkg.SARIFRun{
			{
				Tool: reportpkg.SARIFTool{
					Driver: reportpkg.SARIFDriver{
						Name:    reportpkg.SARIFDriverName,
						Version: reportpkg.SARIFDriverVersion,
						Rules:   rules,
					},
				},
				Results: []reportpkg.SARIFResult(results),
				Invocations: []reportpkg.SARIFInvocation{
					{ExecutionSuccessful: report.Decision != "REJECTED"},
				},
				Properties: reportpkg.SARIFProperties{
					SchemaVersion: report.SchemaVersion,
					PreRelease:    report.PreRelease,
					SourceInput:   report.Source.Input,
					SourceKind:    report.Source.Kind,
					Decision:      report.Decision,
					Note:          report.Note,
				},
			},
		},
	}
}

func inspectSeverityToSARIFLevel(severity string) string {
	return reportpkg.SARIFLevelForSeverity(severity)
}

func inspectArgsRequestJSON(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == "json" {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == "json" {
			return true
		}
	}
	return false
}

func inspectArgsRequestSARIF(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == "sarif" {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == "sarif" {
			return true
		}
	}
	return false
}

func inspectArgsRequestReviewJSON(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == "review-json" {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == "review-json" {
			return true
		}
	}
	return false
}

func extractInspectSourceArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func writeInspectJSONError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, inspectErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = rulepkg.InferIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render inspect error report")
		return exitcode.Error.Int()
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return exitcode.Error.Int()
}

func writeInspectSARIFError(stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, inspectErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = rulepkg.InferIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(buildInspectSARIFErrorReport(report), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render inspect SARIF error report")
		return exitcode.Error.Int()
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return exitcode.Error.Int()
}

func buildInspectSARIFErrorReport(report inspectErrorReport) reportpkg.SARIFDocument {
	ruleID := report.ErrorCode
	if report.RuleID != "" {
		ruleID = report.RuleID
	}
	return reportpkg.SARIFErrorDocument(ruleID, report.ErrorCode, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Source.Input,
		SourceKind:    report.Source.Kind,
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
	})
}

func emitInspectStructuredError(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) bool {
	switch format {
	case "json":
		_ = writeInspectJSONError(stdout, stderr, report)
		return true
	case "sarif":
		_ = writeInspectSARIFError(stdout, stderr, report)
		return true
	case "review-json":
		_ = writeInspectJSONError(stdout, stderr, report)
		return true
	default:
		return false
	}
}

func emitInspectStructuredErrorCode(format string, stdout io.Writer, stderr io.Writer, report inspectErrorReport) int {
	_ = emitInspectStructuredError(format, stdout, stderr, report)
	return exitcode.Error.Int()
}

func normalizeJSONErrorCode(code string, fallback string) string {
	cleanedCode := strings.TrimSpace(code)
	if errorCodePattern.MatchString(cleanedCode) {
		return cleanedCode
	}
	cleanedFallback := strings.TrimSpace(fallback)
	if errorCodePattern.MatchString(cleanedFallback) {
		return cleanedFallback
	}
	return "UNKNOWN_ERROR"
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

func detectSourceKind(input string) string {
	lower := strings.ToLower(input)
	switch {
	case strings.HasPrefix(input, "github:"):
		return "github-source"
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar"
	default:
		return "local-dir"
	}
}

func validateLocalDirInspectSource(input string) error {
	return skillpkg.ValidateLocalDirInspectSource(input, maxSkillFrontmatterBytes)
}

func isInspectSourceNotFoundError(err error) bool {
	return errors.Is(err, errInspectSourceNotFound)
}
