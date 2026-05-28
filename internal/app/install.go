package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
	"github.com/watany-dev/gokui/internal/scan"
	srcpkg "github.com/watany-dev/gokui/internal/source"
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

func readInstallLock(path string) (installLock, error) {
	if err := rejectSymlinkPath(path, "install lockfile", rulepkg.LockfileSymlink.ID); err != nil {
		return installLock{}, err
	}
	linkInfo, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return installLock{}, fmt.Errorf("%s: install lockfile must not be a symlink: %s", rulepkg.LockfileSymlink.ID, path)
	}
	if !linkInfo.Mode().IsRegular() {
		return installLock{}, fmt.Errorf("%s: install lockfile must be a regular file: %s", rulepkg.LockfileSpecialFile.ID, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	defer f.Close()
	if err := ensureInstallLockStableFromOpen(linkInfo, f, path); err != nil {
		return installLock{}, err
	}
	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxInstallLockFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return installLock{}, fmt.Errorf("%s: install lockfile exceeds size limit: %s", rulepkg.LockfileTooLarge.ID, path)
		}
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if !utf8.Valid(raw.Bytes()) {
		return installLock{}, fmt.Errorf("%s: install lockfile must be valid UTF-8: %s", rulepkg.LockfileInvalidUTF8.ID, path)
	}

	var lock installLock
	if err := json.Unmarshal(raw.Bytes(), &lock); err != nil {
		return installLock{}, fmt.Errorf("invalid install lockfile JSON: %s", path)
	}
	if strings.IndexFunc(lock.Schema, isC0OrC1ControlRune) >= 0 {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain C0/C1 control characters at %s: %s", path, lock.Schema)
	}
	if strings.TrimSpace(lock.Schema) != lock.Schema {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain leading or trailing whitespace at %s: %s", path, lock.Schema)
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Schema) {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters at %s: %s", path, lock.Schema)
	}
	if lock.Schema != lockSchemaVersion {
		return installLock{}, fmt.Errorf("unsupported install lockfile schema at %s: %s", path, lock.Schema)
	}
	return lock, nil
}

func ensureInstallLockStableFromOpen(previous os.FileInfo, opened fileInfoStatter, path string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     path,
		StatError: func(path string) error {
			return fmt.Errorf("failed to read install lockfile: %s", path)
		},
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: install lockfile changed during read: %s", rulepkg.LockfileSourceChangedDuringRead.ID, path)
		},
	}.CheckOpened(opened)
}

func provenanceMatches(existing installLock, incoming installLock) bool {
	if existing.Schema != incoming.Schema {
		return false
	}
	if existing.Name != incoming.Name {
		return false
	}
	if existing.Source != incoming.Source {
		return false
	}
	if existing.Policy.Profile != incoming.Policy.Profile {
		return false
	}
	if existing.Skill.RootSHA256 != incoming.Skill.RootSHA256 {
		return false
	}
	return true
}

func validateInstallLockForProvenanceReuse(lock installLock, expectedSkillName string) error {
	if strings.IndexFunc(lock.Schema, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock schema must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Schema) {
		return fmt.Errorf("lock schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if strings.TrimSpace(lock.Schema) != lock.Schema {
		return fmt.Errorf("lock schema must not contain leading or trailing whitespace")
	}
	if lock.Schema != lockSchemaVersion {
		return fmt.Errorf("unsupported install lock schema: %s", lock.Schema)
	}
	trimmedName := strings.TrimSpace(lock.Name)
	if strings.IndexFunc(lock.Name, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock name must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Name) {
		return fmt.Errorf("lock name must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedName == "" {
		return fmt.Errorf("lock name is empty")
	}
	if trimmedName != lock.Name {
		return fmt.Errorf("lock name must not contain leading or trailing whitespace")
	}
	if expectedSkillName != "" && lock.Name != expectedSkillName {
		return fmt.Errorf("lock name does not match target skill directory: lock=%s target=%s", lock.Name, expectedSkillName)
	}

	trimmedInstalledAt := strings.TrimSpace(lock.InstalledAt)
	if strings.IndexFunc(lock.InstalledAt, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock installed_at must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.InstalledAt) {
		return fmt.Errorf("lock installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedInstalledAt == "" {
		return fmt.Errorf("lock installed_at is empty")
	}
	if trimmedInstalledAt != lock.InstalledAt {
		return fmt.Errorf("lock installed_at must not contain leading or trailing whitespace")
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return fmt.Errorf("lock installed_at must be RFC3339")
	}

	trimmedProfile := strings.TrimSpace(lock.Policy.Profile)
	if strings.IndexFunc(lock.Policy.Profile, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy profile must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Profile) {
		return fmt.Errorf("lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedProfile == "" {
		return fmt.Errorf("lock policy profile is empty")
	}
	if policypkg.NormalizeProfile(trimmedProfile).String() != lock.Policy.Profile {
		return fmt.Errorf("lock policy profile must be canonical lowercase without surrounding whitespace")
	}
	if _, err := policypkg.ParseProfile(lock.Policy.Profile); err != nil {
		return fmt.Errorf("lock policy profile is unsupported: %s", lock.Policy.Profile)
	}
	trimmedDecision := strings.TrimSpace(lock.Policy.Decision)
	if strings.IndexFunc(lock.Policy.Decision, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy decision must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Decision) {
		return fmt.Errorf("lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedDecision != lock.Policy.Decision {
		return fmt.Errorf("lock policy decision must not contain leading or trailing whitespace")
	}
	if lock.Policy.Decision != "pass" {
		return fmt.Errorf("lock policy decision must be canonical lowercase pass")
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return fmt.Errorf("lock findings summary is invalid: %v", err)
	}
	if err := policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides).Validate(); err != nil {
		return fmt.Errorf("lock policy severity_overrides is invalid: %v", err)
	}

	trimmedKind := strings.TrimSpace(lock.Source.Kind)
	if strings.IndexFunc(lock.Source.Kind, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source kind must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Kind) {
		return fmt.Errorf("lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedKind == "" {
		return fmt.Errorf("lock source kind is empty")
	}
	if trimmedKind != lock.Source.Kind {
		return fmt.Errorf("lock source kind must not contain leading or trailing whitespace")
	}
	if trimmedKind != strings.ToLower(trimmedKind) {
		return fmt.Errorf("lock source kind must be canonical lowercase")
	}
	trimmedInput := strings.TrimSpace(lock.Source.Input)
	if strings.IndexFunc(lock.Source.Input, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source input must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Input) {
		return fmt.Errorf("lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedInput == "" {
		return fmt.Errorf("lock source input is empty")
	}
	if trimmedInput != lock.Source.Input {
		return fmt.Errorf("lock source input must not contain leading or trailing whitespace")
	}
	if detectSourceKind(trimmedInput) != trimmedKind {
		return fmt.Errorf("lock source kind does not match source input")
	}

	expectedType := sourceTypeFromKind(trimmedKind)
	if expectedType == "unknown" {
		return fmt.Errorf("unsupported lock source kind: %s", trimmedKind)
	}
	trimmedType := strings.TrimSpace(lock.Source.Type)
	if strings.IndexFunc(lock.Source.Type, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source type must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Type) {
		return fmt.Errorf("lock source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedType == "" {
		return fmt.Errorf("lock source type is empty")
	}
	if trimmedType != lock.Source.Type {
		return fmt.Errorf("lock source type must not contain leading or trailing whitespace")
	}
	if trimmedType != strings.ToLower(trimmedType) {
		return fmt.Errorf("lock source type must be canonical lowercase")
	}
	if trimmedType != expectedType {
		return fmt.Errorf("source type mismatch for kind %s: expected %s, got %s", trimmedKind, expectedType, trimmedType)
	}

	if trimmedKind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(trimmedInput)
		if err != nil {
			return fmt.Errorf("invalid github source input in lock: %v", err)
		}
		if trimmedInput != canonicalGitHubSourceInput(spec) {
			return fmt.Errorf("github lock source input must be canonical")
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return fmt.Errorf("github lock source must be commit-pinned")
		}
	} else {
		if trimmedInput != filepath.Clean(trimmedInput) {
			return fmt.Errorf("lock source input must be a canonical cleaned path for local/archive sources")
		}
	}

	if !isCanonicalSHA256Hex(lock.Skill.RootSHA256) {
		return fmt.Errorf("lock skill root_sha256 must be a canonical lowercase 64-char hex digest")
	}
	if len(lock.Skill.Files) == 0 {
		return fmt.Errorf("lock skill files is empty")
	}
	seen := make(map[string]struct{}, len(lock.Skill.Files))
	for _, file := range lock.Skill.Files {
		if strings.IndexFunc(file.Path, isC0OrC1ControlRune) >= 0 {
			return fmt.Errorf("lock file path is invalid: %s", file.Path)
		}
		if strings.TrimSpace(file.Path) == "" {
			return fmt.Errorf("lock file path is empty")
		}
		if !isValidLockRelativePath(file.Path) {
			return fmt.Errorf("lock file path is invalid: %s", file.Path)
		}
		if _, exists := seen[file.Path]; exists {
			return fmt.Errorf("duplicate lock file path: %s", file.Path)
		}
		seen[file.Path] = struct{}{}
		if !isCanonicalSHA256Hex(file.SHA256) {
			return fmt.Errorf("lock file sha256 is invalid: %s", file.Path)
		}
		if file.Bytes < 0 {
			return fmt.Errorf("lock file bytes is negative: %s", file.Path)
		}
	}

	return nil
}

func validateInstalledContentForIdempotentReuse(skillPath string, lock installLock) error {
	actualFiles, actualRootHash, err := buildFileDigestsForLock(skillPath)
	if err != nil {
		return fmt.Errorf("failed to verify installed skill content digests: %w", err)
	}
	missing, changed, unexpected := diffLockFiles(lock.Skill.Files, actualFiles)
	if len(missing) > 0 || len(changed) > 0 || len(unexpected) > 0 {
		return fmt.Errorf("installed skill content drift detected: missing=%d changed=%d unexpected=%d", len(missing), len(changed), len(unexpected))
	}
	if lock.Skill.RootSHA256 != actualRootHash {
		return fmt.Errorf("installed skill root hash drift detected: expected %s, got %s", lock.Skill.RootSHA256, actualRootHash)
	}
	if ok, detail := verifyInstallReport(skillPath, lock); !ok {
		return fmt.Errorf("install report integrity check failed: %s", detail)
	}
	if lock.Source.Kind == "github-source" {
		if err := verifyInstalledSourceMetadata(skillPath, source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		}); err != nil {
			return fmt.Errorf("installed github source metadata drift detected: %w", err)
		}
	}
	return nil
}
