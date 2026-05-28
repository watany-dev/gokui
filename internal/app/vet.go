package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	"github.com/watany-dev/gokui/internal/scan"
)

type vetDeps struct {
	LoadUserPolicy       func() (policypkg.Config, bool, error)
	LoadRepositoryPolicy func(string) (policypkg.Config, bool, error)
	PrepareInspectSource func(input string, sourceKind string) (string, func(), error)
}

func defaultVetDeps() vetDeps {
	return vetDeps{
		LoadUserPolicy:       policypkg.LoadUserPolicy,
		LoadRepositoryPolicy: policypkg.LoadRepositoryPolicy,
		PrepareInspectSource: prepareInspectSource,
	}
}

func runVet(args []string, stdout io.Writer, stderr io.Writer) int {
	return runVetWithDeps(args, stdout, stderr, defaultVetDeps())
}

func runVetWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps vetDeps) int {
	requestedFormat, _ := requestedStructuredFormat(args, true)
	deps = normalizeVetDeps(deps)
	input, format, profile, profileSet, err := parseVetArgs(args)
	if err != nil {
		report := inspectArgsErrorReport("vet", args, err)
		return writeArgsParseError(requestedFormat, stderr, err,
			func() int { return writeInspectJSONError(stdout, stderr, report) },
			func() int { return writeInspectSARIFError(stdout, stderr, report) },
		)
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

	skillRoot, cleanup, prepErr := deps.PrepareInspectSource(input, sourceKind)
	if cleanup != nil {
		defer cleanup()
	}
	if prepErr != nil {
		errorCode := inspectErrorCodeSourcePrepareFailed
		if isInspectSourceNotFoundError(prepErr) {
			errorCode = inspectErrorCodeSourceNotFound
		}
		errorReport := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     errorCode,
			Message:       prepErr.Error(),
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet source preparation failed",
		}
		if emitInspectStructuredError(format, stdout, stderr, errorReport) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, prepErr.Error())
		return exitcode.Error.Int()
	}
	scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
	if scanErr != nil {
		errorReport := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     inspectErrorCodeScanFailed,
			Message:       scanErr.Error(),
			Source: source{
				Input: input,
				Kind:  sourceKind,
			},
			Note: "vet scanning failed",
		}
		if emitInspectStructuredError(format, stdout, stderr, errorReport) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, scanErr.Error())
		return exitcode.Error.Int()
	}

	findings, _ := toInspectFindings(scanFindings)
	report := buildVetReportFromFindings(input, sourceKind, profile, findings, rejectSet)

	return writeVetSuccessReport(format, report, stdout)
}

func buildVetReportFromFindings(input string, sourceKind string, profile string, findings []inspectFinding, rejectSet map[string]struct{}) inspectReport {
	return inspectReport{
		SchemaVersion: reportSchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: input,
			Kind:  sourceKind,
		},
		Decision: decisionForInspectFindings(findings, rejectSet),
		Findings: findings,
		Note:     fmt.Sprintf("pre-release inspect includes structural and markdown checks (vet profile=%s)", profile),
	}
}
