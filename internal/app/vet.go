package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	policypkg "github.com/watany-dev/gokui/internal/policy"
)

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
