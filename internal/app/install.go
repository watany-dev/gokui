package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
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
	loadUserPolicyConfig             = policypkg.LoadUserPolicy
	loadRepositoryPolicyConfig       = policypkg.LoadRepositoryPolicy
)

const (
	ruleLockfileTooLarge                = "LOCKFILE_TOO_LARGE"
	ruleLockfileInvalidUTF8             = "LOCKFILE_INVALID_UTF8"
	ruleLockfileSymlink                 = "LOCKFILE_SYMLINK_DETECTED"
	ruleLockfileSpecialFile             = "LOCKFILE_SPECIAL_FILE"
	ruleInstallTargetSymlink            = "INSTALL_TARGET_SYMLINK_DETECTED"
	ruleInstallTargetEntrySymlink       = "INSTALL_TARGET_ENTRY_SYMLINK_DETECTED"
	ruleInstallSourceFileCountExceeded  = "INSTALL_SOURCE_FILE_COUNT_EXCEEDED"
	ruleInstallSourceTotalBytesExceeded = "INSTALL_SOURCE_TOTAL_BYTES_EXCEEDED"
	ruleInstallSourceFileTooLarge       = "INSTALL_SOURCE_FILE_TOO_LARGE"
	ruleInstallSourceSymlink            = "INSTALL_SOURCE_SYMLINK_DETECTED"
	ruleInstallSourceSpecialFile        = "INSTALL_SOURCE_SPECIAL_FILE"
	ruleInstallSourceChanged            = "INSTALL_SOURCE_CHANGED_DURING_COPY"
	ruleInstallDigestSymlink            = "INSTALL_DIGEST_SYMLINK_DETECTED"
	ruleInstallDigestFileCountExceeded  = "INSTALL_DIGEST_FILE_COUNT_EXCEEDED"
	ruleInstallDigestTotalBytesExceeded = "INSTALL_DIGEST_TOTAL_BYTES_EXCEEDED"
	ruleInstallDigestFileTooLarge       = "INSTALL_DIGEST_FILE_TOO_LARGE"
	ruleInstallDigestSpecialFile        = "INSTALL_DIGEST_SPECIAL_FILE"
	ruleInstallDigestSourceChanged      = "INSTALL_DIGEST_SOURCE_CHANGED_DURING_HASH"
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

type installLock struct {
	Schema      string             `json:"schema"`
	Name        string             `json:"name"`
	InstalledAt string             `json:"installed_at"`
	Source      lockSource         `json:"source"`
	Skill       lockSkill          `json:"skill"`
	Policy      lockPolicy         `json:"policy"`
	Findings    lockFindingSummary `json:"findings"`
}

type lockSource struct {
	Type  string `json:"type"`
	Input string `json:"input"`
	Kind  string `json:"kind"`
}

type lockSkill struct {
	RootSHA256 string         `json:"root_sha256"`
	Files      []lockFileHash `json:"files"`
}

type lockFileHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type lockPolicy struct {
	Profile           string                  `json:"profile"`
	Decision          string                  `json:"decision"`
	SeverityOverrides []severityOverrideAudit `json:"severity_overrides"`
}

type lockFindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
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

func runInstall(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := installArgsRequestJSON(args)
	requestedSARIF := installArgsRequestSARIF(args)

	parsed, err := parseInstallArgs(args)
	if err != nil {
		if requestedJSON {
			sourceArg := extractInstallSourceArg(args)
			sourceKind := detectSourceKind(sourceArg)
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
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
				Status:        "ERROR",
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
		return 1
	}
	loadedPolicy, foundPolicy, policyErr := loadUserPolicyConfig()
	if policyErr != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, policyErr.Error())
		return 1
	}
	sourceKind := detectSourceKind(parsed.Source)

	if _, statErr := os.Stat(parsed.Source); statErr != nil {
		if sourceKind != "github-source" {
			if errors.Is(statErr, os.ErrNotExist) {
				if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
					SchemaVersion: reportSchemaVersion,
					Status:        "ERROR",
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
					return 1
				}
				_, _ = fmt.Fprintf(stderr, "install source not found: %s\n", parsed.Source)
				return 1
			}
			accessErr := fmt.Sprintf("failed to access install source: %v", statErr)
			if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
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
				return 1
			}
			_, _ = fmt.Fprintln(stderr, accessErr)
			return 1
		}
	}

	skillRoot, cleanup, err := preparePolicyEvaluationSource(parsed.Source, sourceKind)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	effectivePolicy := loadedPolicy
	effectivePolicyLoaded := foundPolicy
	if shouldApplyRepositoryPolicy(sourceKind) {
		repoPolicy, repoPolicyFound, repoPolicyErr := loadRepositoryPolicyConfig(skillRoot)
		if repoPolicyErr != nil {
			if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
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
				return 1
			}
			_, _ = fmt.Fprintln(stderr, repoPolicyErr.Error())
			return 1
		}
		if repoPolicyFound {
			effectivePolicy = repoPolicy
			effectivePolicyLoaded = true
		}
	}
	if !parsed.ProfileSet && effectivePolicyLoaded && strings.TrimSpace(effectivePolicy.DefaultProfile) != "" {
		parsed.Profile = effectivePolicy.DefaultProfile
	}
	parsed.Profile = normalizePolicyProfile(parsed.Profile)

	if !isSupportedPolicyProfile(parsed.Profile) {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeProfileUnsupported,
			Message:       fmt.Sprintf("unsupported profile: %s (supported: %s)", parsed.Profile, supportedPolicyProfilesCSV()),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install policy profile validation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "unsupported profile: %s (supported: %s)\n", parsed.Profile, supportedPolicyProfilesCSV())
		return 1
	}
	if err := validateInstallOverridesPolicy(parsed.Profile, parsed.Overrides, effectivePolicyLoaded, effectivePolicy); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	rejectSet, err := effectiveRejectSeveritySetForProfile(parsed.Profile, effectivePolicyLoaded, effectivePolicy)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	findings, decision, overrides, err := evaluateSkillWithOverrides(skillRoot, parsed.Profile, parsed.Overrides, rejectSet)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	installSource, err := resolveSourceForInstall(skillRoot, parsed.Source, sourceKind)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
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

	if decision == "REJECTED" {
		report.ErrorCode = installErrorCodePolicyRejected
		if parsed.Format == "json" {
			out, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "failed to render install report")
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return 2
		}
		if parsed.Format == "sarif" {
			out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
			return 2
		}
		if parsed.Format == "compact" {
			_, _ = fmt.Fprintf(stdout, "%s\n", buildInstallCompactSummary(report, parsed.Target))
			return 2
		}
		_, _ = fmt.Fprintln(stdout, "gokui install report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
		_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
		_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
		_, _ = fmt.Fprintln(stdout, "not installed")
		for _, finding := range report.Findings {
			_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
		}
		return 2
	}

	targetRoot, targetErr := resolveInstallTarget(parsed.Target)
	if targetErr != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeTargetInvalid,
			Message:       targetErr.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target validation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, targetErr.Error())
		return 1
	}
	if err := rejectSymlinkPath(targetRoot, "install target root", ruleInstallTargetSymlink); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeTargetInvalid,
			Message:       err.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target validation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeTargetPrepareFailed,
			Message:       fmt.Sprintf("failed to create install target root: %v", err),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install target preparation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "failed to create install target root: %v\n", err)
		return 1
	}

	skillName := filepath.Base(filepath.Clean(skillRoot))
	installedPath, installResult, err := installSkillAtomic(skillRoot, targetRoot, skillName, report)
	if err != nil {
		if emitInstallStructuredError(parsed.Format, stdout, stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       err.Error(),
			Source:        installSource,
			Target:        parsed.Target,
			PolicyProfile: parsed.Profile,
			Note:          "install write step failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	report.Installed = true
	report.InstalledPath = installedPath
	if parsed.Format == "json" {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render install report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return 0
	}
	if parsed.Format == "sarif" {
		out, _ := json.MarshalIndent(buildInstallSARIFReport(report, parsed.Target), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return 0
	}
	if parsed.Format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildInstallCompactSummary(report, parsed.Target))
		return 0
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
	return 0
}

func parseInstallArgs(args []string) (installArgs, error) {
	out := installArgs{Profile: "strict", Format: "human"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--target":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --target")
			}
			out.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			out.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--profile":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --profile")
			}
			out.Profile = args[i+1]
			out.ProfileSet = true
			i++
		case strings.HasPrefix(arg, "--profile="):
			out.Profile = strings.TrimPrefix(arg, "--profile=")
			out.ProfileSet = true
		case arg == "--format":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case arg == "--override":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --override")
			}
			out.Overrides = append(out.Overrides, args[i+1])
			i++
		case strings.HasPrefix(arg, "--override="):
			out.Overrides = append(out.Overrides, strings.TrimPrefix(arg, "--override="))
		case strings.HasPrefix(arg, "-"):
			return installArgs{}, fmt.Errorf("unknown install option: %s", arg)
		default:
			if out.Source != "" {
				return installArgs{}, fmt.Errorf("install accepts exactly one source")
			}
			out.Source = arg
		}
	}

	if out.Source == "" {
		return installArgs{}, fmt.Errorf("install source is required")
	}
	if out.Target == "" {
		return installArgs{}, fmt.Errorf("install target is required")
	}
	if out.Format != "human" && out.Format != "json" && out.Format != "sarif" && out.Format != "compact" {
		return installArgs{}, fmt.Errorf("unsupported install format: %s", out.Format)
	}
	if len(out.Overrides) > 0 {
		seen := make(map[string]struct{}, len(out.Overrides))
		normalized := make([]string, 0, len(out.Overrides))
		for _, override := range out.Overrides {
			ruleID := strings.TrimSpace(override)
			if !errorCodePattern.MatchString(ruleID) {
				return installArgs{}, fmt.Errorf("invalid override rule id: %s", override)
			}
			if _, ok := seen[ruleID]; ok {
				continue
			}
			seen[ruleID] = struct{}{}
			normalized = append(normalized, ruleID)
		}
		sort.Strings(normalized)
		out.Overrides = normalized
	}
	return out, nil
}

func buildInstallSARIFReport(report installReport, target string) inspectSARIFReport {
	inspectEquivalent := inspectReport{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		Source:        report.Source,
		Decision:      report.Decision,
		Findings:      report.Findings,
		Note: fmt.Sprintf(
			"install target=%s profile=%s installed=%t path=%s error_code=%s overrides=%d; %s",
			target,
			report.PolicyProfile,
			report.Installed,
			report.InstalledPath,
			report.ErrorCode,
			len(report.SeverityOverrides),
			report.Note,
		),
	}
	return buildInspectSARIFReport(inspectEquivalent)
}

func buildInstallCompactSummary(report installReport, target string) string {
	critical := 0
	high := 0
	medium := 0
	low := 0
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}
	}
	return fmt.Sprintf(
		"install decision=%s findings=%d critical=%d high=%d medium=%d low=%d overrides=%d installed=%t profile=%s target=%q source_kind=%s source=%q error_code=%s",
		report.Decision,
		len(report.Findings),
		critical,
		high,
		medium,
		low,
		len(report.SeverityOverrides),
		report.Installed,
		report.PolicyProfile,
		target,
		report.Source.Kind,
		report.Source.Input,
		report.ErrorCode,
	)
}

func installArgsRequestJSON(args []string) bool {
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

func installArgsRequestSARIF(args []string) bool {
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

func extractInstallSourceArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--target" || arg == "--profile" || arg == "--format" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--target=") || strings.HasPrefix(arg, "--profile=") || strings.HasPrefix(arg, "--format=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func extractInstallTargetArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--target" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--target=") {
			return strings.TrimPrefix(args[i], "--target=")
		}
	}
	return ""
}

func extractInstallProfileArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--profile" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--profile=") {
			return strings.TrimPrefix(args[i], "--profile=")
		}
	}
	return "strict"
}

func writeInstallJSONError(stdout io.Writer, stderr io.Writer, report installErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, installErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render install error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func writeInstallSARIFError(stdout io.Writer, stderr io.Writer, report installErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, installErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(buildInstallSARIFErrorReport(report), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render install sarif error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func buildInstallSARIFErrorReport(report installErrorReport) inspectSARIFReport {
	ruleID := report.ErrorCode
	if report.RuleID != "" {
		ruleID = report.RuleID
	}
	return inspectSARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []inspectSARIFRun{
			{
				Tool: inspectSARIFTool{
					Driver: inspectSARIFDriver{
						Name:    "gokui",
						Version: "pre-release",
						Rules: []inspectSARIFRule{
							{
								ID: ruleID,
								ShortDescription: inspectSARIFMessageContainer{
									Text: report.ErrorCode,
								},
							},
						},
					},
				},
				Results: []inspectSARIFResult{
					{
						RuleID:  ruleID,
						Level:   "error",
						Message: inspectSARIFMessageContainer{Text: report.Message},
					},
				},
				Invocations: []inspectSARIFInvocation{
					{ExecutionSuccessful: false},
				},
				Properties: inspectSARIFProperties{
					SchemaVersion: report.SchemaVersion,
					PreRelease:    true,
					SourceInput:   report.Source.Input,
					SourceKind:    report.Source.Kind,
					Decision:      report.Status,
					Note: fmt.Sprintf(
						"target=%s profile=%s; %s; error_code=%s",
						report.Target,
						report.PolicyProfile,
						report.Note,
						report.ErrorCode,
					),
				},
			},
		},
	}
}

func emitInstallStructuredError(format string, stdout io.Writer, stderr io.Writer, report installErrorReport) bool {
	switch format {
	case "json":
		_ = writeInstallJSONError(stdout, stderr, report)
		return true
	case "sarif":
		_ = writeInstallSARIFError(stdout, stderr, report)
		return true
	default:
		return false
	}
}

func validateInstallOverridesPolicy(profile string, overrides []string, policyLoaded bool, cfg policypkg.Config) error {
	if len(overrides) == 0 {
		return nil
	}
	normalizedProfile := normalizePolicyProfile(profile)
	if normalizedProfile == policyProfileResearch {
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
	normalizedProfile := normalizePolicyProfile(profile)
	if !isSupportedPolicyProfile(normalizedProfile) {
		return nil, "", nil, fmt.Errorf("unsupported profile: %s (supported: %s)", normalizedProfile, supportedPolicyProfilesCSV())
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
			decision = "REJECTED"
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

type installResult string

const (
	installResultInstalled        installResult = "installed"
	installResultAlreadyInstalled installResult = "already-installed"
)

func installSkillAtomic(skillRoot string, targetRoot string, skillName string, report installReport) (string, installResult, error) {
	finalPath := filepath.Join(targetRoot, skillName)
	if err := rejectSymlinkPath(finalPath, "install target entry", ruleInstallTargetEntrySymlink); err != nil {
		return "", "", err
	}

	stagingRoot, err := os.MkdirTemp(targetRoot, ".gokui-install-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create install staging directory: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagedSkill := filepath.Join(stagingRoot, skillName)
	if err := copyTreeNormalized(skillRoot, stagedSkill); err != nil {
		return "", "", err
	}

	report.InstalledPath = finalPath
	report.Installed = true
	if err := writeInstallMetadata(stagedSkill, report); err != nil {
		return "", "", err
	}

	stagedLock, err := readInstallLock(filepath.Join(stagedSkill, installLockFile))
	if err != nil {
		return "", "", err
	}

	finalInfo, err := os.Stat(finalPath)
	if err == nil {
		if !finalInfo.IsDir() {
			return "", "", fmt.Errorf("install target already contains non-directory path: %s", finalPath)
		}

		existingLock, readErr := readInstallLock(filepath.Join(finalPath, installLockFile))
		if readErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s", finalPath)
		}
		if validateErr := validateInstallLockForProvenanceReuse(existingLock, skillName); validateErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s (%v)", finalPath, validateErr)
		}
		if !provenanceMatches(existingLock, stagedLock) {
			return "", "", fmt.Errorf("install target already contains skill from different provenance: %s", finalPath)
		}
		if integrityErr := validateInstalledContentForIdempotentReuse(finalPath, existingLock); integrityErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s (%v)", finalPath, integrityErr)
		}
		return finalPath, installResultAlreadyInstalled, nil
	}
	if !os.IsNotExist(err) {
		return "", "", fmt.Errorf("failed to check install target: %w", err)
	}

	if err := os.Rename(stagedSkill, finalPath); err != nil {
		return "", "", fmt.Errorf("failed to finalize install: %w", err)
	}

	return finalPath, installResultInstalled, nil
}

func copyTreeNormalized(srcRoot string, dstRoot string) error {
	if err := ensureInstallTreeRoot(srcRoot, "install source", ruleInstallSourceSymlink, ruleInstallSourceSpecialFile); err != nil {
		return err
	}
	files := 0
	var totalBytes int64
	return filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return fmt.Errorf("failed to compute install path: %w", err)
		}
		if rel == "." {
			return os.MkdirAll(dstRoot, 0o755)
		}

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat source file during install: %w", err)
		}
		if srcInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: install source contains symlink: %s", ruleInstallSourceSymlink, rel)
		}
		destPath := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			return os.MkdirAll(destPath, 0o755)
		}
		if !srcInfo.Mode().IsRegular() {
			return fmt.Errorf("%s: install source contains non-regular file: %s", ruleInstallSourceSpecialFile, rel)
		}
		if srcInfo.Size() > installMaxCopyFileBytes {
			return fmt.Errorf("%s: install source file exceeds size limit: %s", ruleInstallSourceFileTooLarge, rel)
		}
		files++
		if files > installMaxCopyFiles {
			return fmt.Errorf("%s: install source exceeds max file count: %d", ruleInstallSourceFileCountExceeded, installMaxCopyFiles)
		}
		remainingTotal := installMaxCopyTotalBytes - totalBytes
		if remainingTotal <= 0 {
			return fmt.Errorf("%s: install source exceeds max total bytes: %d", ruleInstallSourceTotalBytesExceeded, installMaxCopyTotalBytes)
		}
		if srcInfo.Size() > remainingTotal {
			return fmt.Errorf("%s: install source exceeds max total bytes: %d", ruleInstallSourceTotalBytesExceeded, installMaxCopyTotalBytes)
		}
		maxCopyBytes := installMaxCopyFileBytes
		if remainingTotal < maxCopyBytes {
			maxCopyBytes = remainingTotal
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("failed to create install directory: %w", err)
		}
		written, err := copyFileWithModeChecked(path, destPath, 0o644, maxCopyBytes, srcInfo)
		if err != nil {
			return err
		}
		totalBytes += written
		return nil
	})
}

func copyFileWithModeChecked(src string, dst string, mode os.FileMode, maxBytes int64, expectedInfo os.FileInfo) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer in.Close()
	if expectedInfo != nil {
		if err := ensureInstallSourceStableFromOpen(expectedInfo, in, src); err != nil {
			return 0, err
		}
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	written, err := copyWithStrictLimit(out, in, maxBytes)
	if err != nil {
		_ = os.Remove(dst)
		if limitio.IsSizeExceeded(err) {
			return 0, fmt.Errorf("%s: install source file exceeds size limit during copy: %s", ruleInstallSourceFileTooLarge, src)
		}
		return 0, fmt.Errorf("failed to copy file contents: %w", err)
	}
	return written, nil
}

func copyWithStrictLimit(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	return limitio.CopyWithStrictLimit(dst, src, maxBytes)
}

func writeInstallMetadata(stagedSkill string, report installReport) error {
	if report.Source.Kind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(report.Source.Input)
		if err != nil {
			return fmt.Errorf("invalid github source while writing source metadata: %w", err)
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return fmt.Errorf("github source metadata requires commit-pinned ref")
		}
		_, rootHash, err := buildFileDigestsFiltered(stagedSkill, map[string]struct{}{
			sourceMetadataFile: {},
			installReportFile:  {},
			installLockFile:    {},
		})
		if err != nil {
			return err
		}
		if err := writeSourceMetadata(stagedSkill, sourceMetadata{
			Schema:          sourceMetadataSchemaVersion,
			SourceInput:     report.Source.Input,
			SourceKind:      report.Source.Kind,
			ResolvedRef:     spec.Ref,
			FetchedAt:       time.Now().UTC().Format(time.RFC3339),
			SkillRootSHA256: rootHash,
		}); err != nil {
			return err
		}
	}

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render install report: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagedSkill, installReportFile), reportBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write install report: %w", err)
	}

	lock, err := buildInstallLock(stagedSkill, report)
	if err != nil {
		return err
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render install lockfile: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagedSkill, installLockFile), lockBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write install lockfile: %w", err)
	}
	return nil
}

func buildInstallLock(stagedSkill string, report installReport) (installLock, error) {
	files, rootHash, err := buildFileDigestsForLock(stagedSkill)
	if err != nil {
		return installLock{}, err
	}

	summary := lockFindingSummary{}
	for _, finding := range report.Findings {
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

	skillName := filepath.Base(filepath.Clean(stagedSkill))
	return installLock{
		Schema:      lockSchemaVersion,
		Name:        skillName,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Source: lockSource{
			Type:  sourceTypeFromKind(report.Source.Kind),
			Input: report.Source.Input,
			Kind:  report.Source.Kind,
		},
		Skill: lockSkill{
			RootSHA256: rootHash,
			Files:      files,
		},
		Policy: lockPolicy{
			Profile:           report.PolicyProfile,
			Decision:          strings.ToLower(report.Decision),
			SeverityOverrides: cloneSeverityOverrides(report.SeverityOverrides),
		},
		Findings: summary,
	}, nil
}

func sourceTypeFromKind(kind string) string {
	switch kind {
	case "local-dir":
		return "local"
	case "zip", "tar":
		return "archive"
	case "github-source":
		return "github"
	default:
		return "unknown"
	}
}

func buildFileDigestsForLock(root string) ([]lockFileHash, string, error) {
	exclude := map[string]struct{}{
		installLockFile: {},
	}
	return buildFileDigestsFiltered(root, exclude)
}

func buildFileDigestsFiltered(root string, exclude map[string]struct{}) ([]lockFileHash, string, error) {
	if err := ensureInstallTreeRoot(root, "digest input", ruleInstallDigestSymlink, ruleInstallDigestSpecialFile); err != nil {
		return nil, "", fmt.Errorf("%w: %w", errDigestBuildFailed, err)
	}
	files := make([]lockFileHash, 0, 32)
	digestedFiles := 0
	var totalBytes int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("failed to compute digest path: %w", err)
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file for digest: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: digest input contains symlink: %s", ruleInstallDigestSymlink, rel)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: digest input contains non-regular file: %s", ruleInstallDigestSpecialFile, rel)
		}
		if _, skip := exclude[rel]; skip {
			return nil
		}
		if info.Size() > installMaxDigestFileBytes {
			return fmt.Errorf("%s: digest input file exceeds size limit: %s", ruleInstallDigestFileTooLarge, rel)
		}
		digestedFiles++
		if digestedFiles > installMaxDigestFiles {
			return fmt.Errorf("%s: digest input exceeds max file count: %d", ruleInstallDigestFileCountExceeded, installMaxDigestFiles)
		}
		totalBytes += info.Size()
		if totalBytes > installMaxDigestTotalBytes {
			return fmt.Errorf("%s: digest input exceeds max total bytes: %d", ruleInstallDigestTotalBytesExceeded, installMaxDigestTotalBytes)
		}
		sum, size, err := hashFileWithLimitChecked(path, installMaxDigestFileBytes, info)
		if err != nil {
			if errors.Is(err, limitio.ErrSizeExceeded) {
				return fmt.Errorf("%s: digest input file exceeds size limit: %s", ruleInstallDigestFileTooLarge, rel)
			}
			return err
		}
		files = append(files, lockFileHash{
			Path:   rel,
			SHA256: sum,
			Bytes:  size,
		})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errDigestBuildFailed, err)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	rootHasher := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(rootHasher, file.Path)
		_, _ = io.WriteString(rootHasher, "\x00")
		_, _ = io.WriteString(rootHasher, file.SHA256)
		_, _ = io.WriteString(rootHasher, "\x00")
	}
	return files, hex.EncodeToString(rootHasher.Sum(nil)), nil
}

func ensureInstallTreeRoot(root string, label string, symlinkRuleID string, specialRuleID string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %s root must not be a symlink: %s", symlinkRuleID, label, root)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("%s: %s root must be a directory: %s", specialRuleID, label, root)
	}
	return nil
}

func hashFileWithLimitChecked(path string, maxBytes int64, expectedInfo os.FileInfo) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer f.Close()
	if expectedInfo != nil {
		if err := ensureInstallDigestStableFromOpen(expectedInfo, f, path); err != nil {
			return "", 0, err
		}
	}

	hasher := sha256.New()
	var n int64
	if maxBytes >= 0 {
		n, err = limitio.CopyWithStrictLimit(hasher, f, maxBytes)
	} else {
		n, err = io.Copy(hasher, f)
	}
	if err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("failed to hash file: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

func ensureInstallSourceStableFromOpen(previous os.FileInfo, opened fileInfoStatter, src string) error {
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("failed to open source file: %s", src)
	}
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: install source file changed during copy: %s", ruleInstallSourceChanged, src)
}

func ensureInstallDigestStableFromOpen(previous os.FileInfo, opened fileInfoStatter, path string) error {
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("failed to open file for hashing: %s", path)
	}
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: digest input file changed during hash: %s", ruleInstallDigestSourceChanged, path)
}

func readInstallLock(path string) (installLock, error) {
	if err := rejectSymlinkPath(path, "install lockfile", ruleLockfileSymlink); err != nil {
		return installLock{}, err
	}
	linkInfo, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return installLock{}, fmt.Errorf("%s: install lockfile must not be a symlink: %s", ruleLockfileSymlink, path)
	}
	if !linkInfo.Mode().IsRegular() {
		return installLock{}, fmt.Errorf("%s: install lockfile must be a regular file: %s", ruleLockfileSpecialFile, path)
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
			return installLock{}, fmt.Errorf("%s: install lockfile exceeds size limit: %s", ruleLockfileTooLarge, path)
		}
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if !utf8.Valid(raw.Bytes()) {
		return installLock{}, fmt.Errorf("%s: install lockfile must be valid UTF-8: %s", ruleLockfileInvalidUTF8, path)
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
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: install lockfile changed during read: %s", ruleLockfileSourceChanged, path)
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
	if trimmedName == "" {
		return fmt.Errorf("lock name is empty")
	}
	if strings.IndexFunc(lock.Name, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock name must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Name) {
		return fmt.Errorf("lock name must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedName != lock.Name {
		return fmt.Errorf("lock name must not contain leading or trailing whitespace")
	}
	if expectedSkillName != "" && lock.Name != expectedSkillName {
		return fmt.Errorf("lock name does not match target skill directory: lock=%s target=%s", lock.Name, expectedSkillName)
	}

	trimmedInstalledAt := strings.TrimSpace(lock.InstalledAt)
	if trimmedInstalledAt == "" {
		return fmt.Errorf("lock installed_at is empty")
	}
	if strings.IndexFunc(lock.InstalledAt, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock installed_at must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.InstalledAt) {
		return fmt.Errorf("lock installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedInstalledAt != lock.InstalledAt {
		return fmt.Errorf("lock installed_at must not contain leading or trailing whitespace")
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return fmt.Errorf("lock installed_at must be RFC3339")
	}

	trimmedProfile := strings.TrimSpace(lock.Policy.Profile)
	if trimmedProfile == "" {
		return fmt.Errorf("lock policy profile is empty")
	}
	if strings.IndexFunc(lock.Policy.Profile, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy profile must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Profile) {
		return fmt.Errorf("lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if normalizePolicyProfile(trimmedProfile) != lock.Policy.Profile {
		return fmt.Errorf("lock policy profile must be canonical lowercase without surrounding whitespace")
	}
	if !isSupportedPolicyProfile(lock.Policy.Profile) {
		return fmt.Errorf("lock policy profile is unsupported: %s", lock.Policy.Profile)
	}
	trimmedDecision := strings.TrimSpace(lock.Policy.Decision)
	if trimmedDecision != lock.Policy.Decision {
		return fmt.Errorf("lock policy decision must not contain leading or trailing whitespace")
	}
	if strings.IndexFunc(lock.Policy.Decision, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy decision must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Decision) {
		return fmt.Errorf("lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if lock.Policy.Decision != "pass" {
		return fmt.Errorf("lock policy decision must be canonical lowercase pass")
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return fmt.Errorf("lock findings summary is invalid: %v", err)
	}
	if err := validateSeverityOverrideAudit(lock.Policy.SeverityOverrides); err != nil {
		return fmt.Errorf("lock policy severity_overrides is invalid: %v", err)
	}

	trimmedKind := strings.TrimSpace(lock.Source.Kind)
	if trimmedKind == "" {
		return fmt.Errorf("lock source kind is empty")
	}
	if strings.IndexFunc(lock.Source.Kind, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source kind must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Kind) {
		return fmt.Errorf("lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedKind != lock.Source.Kind {
		return fmt.Errorf("lock source kind must not contain leading or trailing whitespace")
	}
	if trimmedKind != strings.ToLower(trimmedKind) {
		return fmt.Errorf("lock source kind must be canonical lowercase")
	}
	trimmedInput := strings.TrimSpace(lock.Source.Input)
	if trimmedInput == "" {
		return fmt.Errorf("lock source input is empty")
	}
	if strings.IndexFunc(lock.Source.Input, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source input must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Input) {
		return fmt.Errorf("lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
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
