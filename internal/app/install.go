package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

const (
	installReportFile = ".gokui-report.json"
	installLockFile   = "gokui.lock"
)

var (
	maxInstallLockFileBytes    int64 = 1_000_000
	installMaxCopyFiles              = 10_000
	installMaxCopyTotalBytes   int64 = 200 * 1024 * 1024
	installMaxCopyFileBytes    int64 = 20 * 1024 * 1024
	installMaxDigestFiles            = 10_000
	installMaxDigestTotalBytes int64 = 200 * 1024 * 1024
	installMaxDigestFileBytes  int64 = 20 * 1024 * 1024
	errDigestBuildFailed             = errors.New("failed to digest installed files")
)

type installArgs struct {
	Source     string
	Target     string
	Profile    string
	ProfileSet bool
	Format     string
	Overrides  []string
}

type installReport struct {
	SchemaVersion     string                  `json:"schema_version"`
	Source            source                  `json:"source"`
	PolicyProfile     string                  `json:"policy_profile"`
	Decision          string                  `json:"decision"`
	ErrorCode         string                  `json:"error_code"`
	Findings          []inspectFinding        `json:"findings"`
	SeverityOverrides []severityOverrideAudit `json:"severity_overrides"`
	InstalledPath     string                  `json:"installed_path,omitempty"`
	Installed         bool                    `json:"installed"`
	Note              string                  `json:"note"`
}

type installErrorReport struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code"`
	RuleID        string `json:"rule_id,omitempty"`
	Message       string `json:"message"`
	Source        source `json:"source"`
	Target        string `json:"target"`
	PolicyProfile string `json:"policy_profile"`
	Note          string `json:"note"`
}

const (
	installErrorCodeArgsInvalid          = "INSTALL_ARGS_INVALID"
	installErrorCodeProfileUnsupported   = "INSTALL_PROFILE_UNSUPPORTED"
	installErrorCodeSourceNotFound       = "INSTALL_SOURCE_NOT_FOUND"
	installErrorCodeSourcePrepareFailed  = "INSTALL_SOURCE_PREPARE_FAILED"
	installErrorCodeEvaluationFailed     = "INSTALL_EVALUATION_FAILED"
	installErrorCodeSourceMetadataFailed = "INSTALL_SOURCE_METADATA_INVALID"
	installErrorCodeTargetInvalid        = "INSTALL_TARGET_INVALID"
	installErrorCodeTargetPrepareFailed  = "INSTALL_TARGET_PREPARE_FAILED"
	installErrorCodeWriteFailed          = "INSTALL_WRITE_FAILED"
	installErrorCodePolicyRejected       = "INSTALL_POLICY_REJECTED"
	installErrorCodePolicyLoadFailed     = "INSTALL_POLICY_LOAD_FAILED"
	installErrorCodeOverrideNotAllowed   = "INSTALL_OVERRIDE_NOT_ALLOWED"
	installErrorCodeUnknown              = "INSTALL_FAILED"
)

type installDeps struct {
	LoadUserPolicy          func() (policypkg.Config, bool, error)
	LoadRepositoryPolicy    func(string) (policypkg.Config, bool, error)
	PrepareEvaluationSource func(input string, sourceKind string) (string, func(), error)
}

func defaultInstallDeps() installDeps {
	return installDeps{
		LoadUserPolicy:          policypkg.LoadUserPolicy,
		LoadRepositoryPolicy:    policypkg.LoadRepositoryPolicy,
		PrepareEvaluationSource: preparePolicyEvaluationSource,
	}
}

func runInstall(args []string, stdout io.Writer, stderr io.Writer) int {
	return runInstallWithDeps(args, stdout, stderr, defaultInstallDeps())
}

func runInstallWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps installDeps) int {
	requestedFormat, _ := requestedStructuredFormat(args, false)
	deps = normalizeInstallDeps(deps)

	parsed, err := parseInstallArgs(args)
	if err != nil {
		if requestedFormat == formatpkg.JSON {
			sourceArg := extractInstallSourceArg(args)
			sourceKind := detectSourceKind(sourceArg)
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     installErrorCodeArgsInvalid,
				Message:       err.Error(),
				Source: source{
					Input: sourceArg,
					Kind:  sourceKind,
				},
				Target:        extractInstallTargetArg(args),
				PolicyProfile: extractInstallProfileArg(args),
				Note:          "install failed before source evaluation",
			})
		}
		if requestedFormat == formatpkg.SARIF {
			sourceArg := extractInstallSourceArg(args)
			sourceKind := detectSourceKind(sourceArg)
			return writeInstallSARIFError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     installErrorCodeArgsInvalid,
				Message:       err.Error(),
				Source: source{
					Input: sourceArg,
					Kind:  sourceKind,
				},
				Target:        extractInstallTargetArg(args),
				PolicyProfile: extractInstallProfileArg(args),
				Note:          "install failed before source evaluation",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}
	loadedPolicy, foundPolicy, policyErr := deps.LoadUserPolicy()
	if policyErr != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodePolicyLoadFailed,
			Message:       policyErr.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  detectSourceKind(parsed.Source),
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "failed to load user policy profile",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, policyErr.Error())
		return exitcode.Error.Int()
	}
	sourceKind := detectSourceKind(parsed.Source)

	if _, statErr := os.Stat(parsed.Source); statErr != nil {
		if sourceKind != "github-source" {
			if errors.Is(statErr, os.ErrNotExist) {
				if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        reportStatusError,
					ErrorCode:     installErrorCodeSourceNotFound,
					Message:       fmt.Sprintf("install source not found: %s", parsed.Source),
					Source: source{
						Input: parsed.Source,
						Kind:  sourceKind,
					},
					Target:        parsed.Target,
					PolicyProfile: parsed.Profile,
					Note:          "install source must exist before policy evaluation",
				}) {
					return exitcode.Error.Int()
				}
				_, _ = fmt.Fprintf(stderr, "install source not found: %s\n", parsed.Source)
				return exitcode.Error.Int()
			}
			accessErr := fmt.Sprintf("failed to access install source: %v", statErr)
			if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     installErrorCodeSourcePrepareFailed,
				Message:       accessErr,
				Source: source{
					Input: parsed.Source,
					Kind:  sourceKind,
				},
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install source access check failed",
			}) {
				return exitcode.Error.Int()
			}
			_, _ = fmt.Fprintln(stderr, accessErr)
			return exitcode.Error.Int()
		}
	}

	skillRoot, cleanup, err := deps.PrepareEvaluationSource(parsed.Source, sourceKind)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeSourcePrepareFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install source preparation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	effectivePolicy := loadedPolicy
	effectivePolicyLoaded := foundPolicy
	if shouldApplyRepositoryPolicy(sourceKind) {
		repoPolicy, repoPolicyFound, repoPolicyErr := deps.LoadRepositoryPolicy(skillRoot)
		if repoPolicyErr != nil {
			if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     installErrorCodePolicyLoadFailed,
				Message:       repoPolicyErr.Error(),
				Source: source{
					Input: parsed.Source,
					Kind:  sourceKind,
				},
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "failed to load repository policy profile",
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
	if !parsed.ProfileSet && effectivePolicyLoaded && strings.TrimSpace(effectivePolicy.DefaultProfile) != "" {
		parsed.Profile = effectivePolicy.DefaultProfile
	}
	parsed.Profile = policypkg.NormalizeProfile(parsed.Profile).String()

	if _, err := policypkg.ParseProfile(parsed.Profile); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeProfileUnsupported,
			Message:       fmt.Sprintf("unsupported profile: %s (supported: %s)", parsed.Profile, policypkg.SupportedProfilesCSV()),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install policy profile validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "unsupported profile: %s (supported: %s)\n", parsed.Profile, policypkg.SupportedProfilesCSV())
		return exitcode.Error.Int()
	}
	if err := validateInstallOverridesPolicy(parsed.Profile, parsed.Overrides, effectivePolicyLoaded, effectivePolicy); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeOverrideNotAllowed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install override policy validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	rejectSeverities, err := policypkg.EffectiveRejectSeverities(policypkg.NormalizeProfile(parsed.Profile), effectivePolicyLoaded, effectivePolicy)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodePolicyLoadFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "policy reject_severities configuration is invalid",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	rejectSet := rejectSeverities.Strings()

	findings, decision, overrides, err := evaluateSkillWithOverrides(skillRoot, parsed.Profile, parsed.Overrides, rejectSet)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeEvaluationFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install policy evaluation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	installSource, err := resolveSourceForInstall(skillRoot, parsed.Source, sourceKind)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeSourceMetadataFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install source metadata validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	report := installReport{
		SchemaVersion:     reportSchemaVersion,
		Source:            installSource,
		PolicyProfile:     parsed.Profile,
		Decision:          decision,
		Findings:          findings,
		SeverityOverrides: overrides,
		Installed:         false,
		ErrorCode:         "",
		Note:              "pre-release install applies profile-based structural and markdown checks",
	}

	if decision == reportDecisionRejected {
		report.ErrorCode = installErrorCodePolicyRejected
		switch formatpkg.Format(parsed.Format) {
		case formatpkg.JSON:
			out, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "failed to render install report")
				return exitcode.Error.Int()
			}
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return exitcode.Rejected.Int()
		case formatpkg.SARIF:
			out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return exitcode.Rejected.Int()
		case formatpkg.Compact:
			_, _ = fmt.Fprintf(stdout, "%s\n", buildInstallCompactSummary(report, parsed.Target))
			return exitcode.Rejected.Int()
		}
		_, _ = fmt.Fprintln(stdout, "gokui install report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
		_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
		_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
		_, _ = fmt.Fprintln(stdout, "not installed")
		for _, finding := range report.Findings {
			_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
		}
		return exitcode.Rejected.Int()
	}

	targetRoot, targetErr := resolveInstallTarget(parsed.Target)
	if targetErr != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeTargetInvalid,
			Message:       targetErr.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, targetErr.Error())
		return exitcode.Error.Int()
	}
	if err := rejectSymlinkPath(targetRoot, "install target root", rulepkg.InstallTargetSymlink.ID); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeTargetInvalid,
			Message:       err.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeTargetPrepareFailed,
			Message:       fmt.Sprintf("failed to create install target root: %v", err),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target preparation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "failed to create install target root: %v\n", err)
		return exitcode.Error.Int()
	}

	skillName := filepath.Base(filepath.Clean(skillRoot))
	installedPath, installResult, err := installSkillAtomic(skillRoot, targetRoot, skillName, report)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       err.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install write step failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	report.Installed = true
	report.InstalledPath = installedPath
	switch formatpkg.Format(parsed.Format) {
	case formatpkg.JSON:
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render install report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	case formatpkg.SARIF:
		out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	case formatpkg.Compact:
		_, _ = fmt.Fprintf(stdout, "%s\n", buildInstallCompactSummary(report, parsed.Target))
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui install report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	switch installResult {
	case installResultInstalled:
		_, _ = fmt.Fprintf(stdout, "installed: %s\n", installedPath)
	case installResultAlreadyInstalled:
		_, _ = fmt.Fprintf(stdout, "installed: %s (already installed with matching provenance)\n", installedPath)
	default:
		_, _ = fmt.Fprintf(stdout, "installed: %s\n", installedPath)
	}
	return exitcode.OK.Int()
}
