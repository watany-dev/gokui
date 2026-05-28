package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
	"github.com/watany-dev/gokui/internal/scan"
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
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	deps = normalizeInstallDeps(deps)

	parsed, err := parseInstallArgs(args)
	if err != nil {
		if requestedJSON {
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
		if requestedSARIF {
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
		if parsed.Format == "json" {
			out, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "failed to render install report")
				return exitcode.Error.Int()
			}
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return exitcode.Rejected.Int()
		}
		if parsed.Format == "sarif" {
			out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return exitcode.Rejected.Int()
		}
		if parsed.Format == "compact" {
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
	if parsed.Format == "json" {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render install report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	}
	if parsed.Format == "sarif" {
		out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	}
	if parsed.Format == "compact" {
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

func normalizeInstallDeps(deps installDeps) installDeps {
	if deps.LoadUserPolicy == nil {
		deps.LoadUserPolicy = policypkg.LoadUserPolicy
	}
	if deps.LoadRepositoryPolicy == nil {
		deps.LoadRepositoryPolicy = policypkg.LoadRepositoryPolicy
	}
	if deps.PrepareEvaluationSource == nil {
		deps.PrepareEvaluationSource = preparePolicyEvaluationSource
	}
	return deps
}

func validateInstallOverridesPolicy(profile string, overrides []string, policyLoaded bool, cfg policypkg.Config) error {
	if len(overrides) == 0 {
		return nil
	}
	normalizedProfile := policypkg.NormalizeProfile(profile)
	if normalizedProfile == policypkg.ProfileResearch {
		return fmt.Errorf("overrides are not allowed for profile: %s", normalizedProfile)
	}
	if policyLoaded && !cfg.Overrides.Enabled {
		return fmt.Errorf("overrides are disabled by policy configuration")
	}
	if policyLoaded && len(cfg.Overrides.AllowedRuleIDs) > 0 {
		allowed := make(map[string]struct{}, len(cfg.Overrides.AllowedRuleIDs))
		for _, id := range cfg.Overrides.AllowedRuleIDs {
			allowed[id] = struct{}{}
		}
		for _, id := range overrides {
			if _, ok := allowed[id]; !ok {
				return fmt.Errorf("override rule is not allowed by policy: %s", id)
			}
		}
	}
	return nil
}

func evaluateSkillWithOverrides(skillRoot string, profile string, overrideRuleIDs []string, rejectSeveritySet map[string]struct{}) ([]inspectFinding, string, []severityOverrideAudit, error) {
	normalizedProfile := policypkg.NormalizeProfile(profile)
	if _, err := policypkg.ParseProfile(normalizedProfile.String()); err != nil {
		return nil, "", nil, fmt.Errorf("unsupported profile: %s (supported: %s)", normalizedProfile, policypkg.SupportedProfilesCSV())
	}

	scanFindings, err := scan.ScanSkillRoot(skillRoot)
	if err != nil {
		return nil, "", nil, err
	}

	findings := make([]inspectFinding, 0, len(scanFindings))
	overrides := make([]severityOverrideAudit, 0, len(overrideRuleIDs))
	overrideSet := make(map[string]struct{}, len(overrideRuleIDs))
	overrideMatched := make(map[string]struct{}, len(overrideRuleIDs))
	for _, ruleID := range overrideRuleIDs {
		overrideSet[ruleID] = struct{}{}
	}

	decision := "PASS"
	appliedAt := time.Now().UTC().Format(time.RFC3339)
	for _, finding := range scanFindings {
		findings = append(findings, inspectFinding{
			ID:       finding.ID,
			Severity: finding.Severity,
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
		effectiveSeverity := finding.Severity
		if _, ok := overrideSet[finding.ID]; ok {
			overrideMatched[finding.ID] = struct{}{}
			if finding.Severity == "high" {
				effectiveSeverity = "medium"
			}
			overrides = append(overrides, severityOverrideAudit{
				RuleID:            finding.ID,
				PreviousSeverity:  finding.Severity,
				EffectiveSeverity: effectiveSeverity,
				Justification:     "explicit CLI override for install policy decision",
				ApprovedBy:        "local-operator",
				Source:            "cli-override",
				AppliedAt:         appliedAt,
			})
		}
		if _, shouldReject := rejectSeveritySet[strings.ToLower(strings.TrimSpace(effectiveSeverity))]; shouldReject {
			decision = reportDecisionRejected
		}
	}
	for _, ruleID := range overrideRuleIDs {
		if _, ok := overrideMatched[ruleID]; ok {
			continue
		}
		return nil, "", nil, fmt.Errorf("override rule not found in findings: %s", ruleID)
	}
	sort.Slice(overrides, func(i, j int) bool {
		return overrides[i].RuleID < overrides[j].RuleID
	})
	return findings, decision, overrides, nil
}

func resolveInstallTarget(target string) (string, error) {
	if target == "codex" {
		if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
			return filepath.Join(codexHome, "skills"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve home directory for codex target: %w", err)
		}
		return filepath.Join(home, ".codex", "skills"), nil
	}

	if strings.HasPrefix(target, "custom:") {
		custom := strings.TrimSpace(strings.TrimPrefix(target, "custom:"))
		if custom == "" {
			return "", fmt.Errorf("custom target path is required: custom:/path/to/skills")
		}
		cleaned := filepath.Clean(custom)
		if !filepath.IsAbs(cleaned) {
			return "", fmt.Errorf("custom target path must be absolute: %s", custom)
		}
		return cleaned, nil
	}

	return "", fmt.Errorf("unsupported install target: %s", target)
}

func ensureInstallSourceStableFromOpen(previous os.FileInfo, opened fileInfoStatter, src string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     src,
		StatError: func(path string) error {
			return fmt.Errorf("failed to open source file: %s", path)
		},
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: install source file changed during copy: %s", rulepkg.InstallSourceChangedDuringCopy.ID, path)
		},
	}.CheckOpened(opened)
}
