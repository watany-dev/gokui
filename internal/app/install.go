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

	"github.com/watany-dev/gokui/internal/limitio"
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

const (
	ruleLockfileTooLarge                = "LOCKFILE_TOO_LARGE"
	ruleLockfileSymlink                 = "LOCKFILE_SYMLINK_DETECTED"
	ruleLockfileSpecialFile             = "LOCKFILE_SPECIAL_FILE"
	ruleInstallTargetSymlink            = "INSTALL_TARGET_SYMLINK_DETECTED"
	ruleInstallTargetEntrySymlink       = "INSTALL_TARGET_ENTRY_SYMLINK_DETECTED"
	ruleInstallSourceFileCountExceeded  = "INSTALL_SOURCE_FILE_COUNT_EXCEEDED"
	ruleInstallSourceTotalBytesExceeded = "INSTALL_SOURCE_TOTAL_BYTES_EXCEEDED"
	ruleInstallSourceFileTooLarge       = "INSTALL_SOURCE_FILE_TOO_LARGE"
	ruleInstallSourceSpecialFile        = "INSTALL_SOURCE_SPECIAL_FILE"
	ruleInstallDigestSymlink            = "INSTALL_DIGEST_SYMLINK_DETECTED"
	ruleInstallDigestFileCountExceeded  = "INSTALL_DIGEST_FILE_COUNT_EXCEEDED"
	ruleInstallDigestTotalBytesExceeded = "INSTALL_DIGEST_TOTAL_BYTES_EXCEEDED"
	ruleInstallDigestFileTooLarge       = "INSTALL_DIGEST_FILE_TOO_LARGE"
	ruleInstallDigestSpecialFile        = "INSTALL_DIGEST_SPECIAL_FILE"
)

type installArgs struct {
	Source  string
	Target  string
	Profile string
	Format  string
}

type installReport struct {
	SchemaVersion string           `json:"schema_version"`
	Source        source           `json:"source"`
	PolicyProfile string           `json:"policy_profile"`
	Decision      string           `json:"decision"`
	ErrorCode     string           `json:"error_code"`
	Findings      []inspectFinding `json:"findings"`
	InstalledPath string           `json:"installed_path,omitempty"`
	Installed     bool             `json:"installed"`
	Note          string           `json:"note"`
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
	Profile  string `json:"profile"`
	Decision string `json:"decision"`
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
	installErrorCodeUnknown              = "INSTALL_FAILED"
)

func runInstall(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := installArgsRequestJSON(args)

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
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}
	jsonOutput := parsed.Format == "json"
	sourceKind := detectSourceKind(parsed.Source)

	if parsed.Profile != "strict" {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeProfileUnsupported,
				Message:       fmt.Sprintf("unsupported profile: %s (only strict is currently supported)", parsed.Profile),
				Source: source{
					Input: parsed.Source,
					Kind:  sourceKind,
				},
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install currently supports strict profile only",
			})
		}
		_, _ = fmt.Fprintf(stderr, "unsupported profile: %s (only strict is currently supported)\n", parsed.Profile)
		return 1
	}

	if _, statErr := os.Stat(parsed.Source); statErr != nil {
		if sourceKind != "github-source" {
			if errors.Is(statErr, os.ErrNotExist) {
				if jsonOutput {
					return writeInstallJSONError(stdout, stderr, installErrorReport{
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
					})
				}
				_, _ = fmt.Fprintf(stderr, "install source not found: %s\n", parsed.Source)
				return 1
			}
			accessErr := fmt.Sprintf("failed to access install source: %v", statErr)
			if jsonOutput {
				return writeInstallJSONError(stdout, stderr, installErrorReport{
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
				})
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
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
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
			})
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	findings, decision, err := evaluateSkill(skillRoot)
	if err != nil {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
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
			})
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	installSource, err := resolveSourceForInstall(skillRoot, parsed.Source, sourceKind)
	if err != nil {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
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
			})
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	report := installReport{
		SchemaVersion: reportSchemaVersion,
		Source:        installSource,
		PolicyProfile: parsed.Profile,
		Decision:      decision,
		Findings:      findings,
		Installed:     false,
		ErrorCode:     "",
		Note:          "pre-release install applies strict structural and markdown checks",
	}

	if decision == "REJECTED" {
		report.ErrorCode = installErrorCodePolicyRejected
		if jsonOutput {
			out, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				_, _ = fmt.Fprintln(stderr, "failed to render install report")
				return 1
			}
			_, _ = fmt.Fprintf(stdout, "%s\n", out)
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
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeTargetInvalid,
				Message:       targetErr.Error(),
				Source:        installSource,
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install target validation failed",
			})
		}
		_, _ = fmt.Fprintln(stderr, targetErr.Error())
		return 1
	}
	if err := rejectSymlinkPath(targetRoot, "install target root", ruleInstallTargetSymlink); err != nil {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeTargetInvalid,
				Message:       err.Error(),
				Source:        installSource,
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install target validation failed",
			})
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeTargetPrepareFailed,
				Message:       fmt.Sprintf("failed to create install target root: %v", err),
				Source:        installSource,
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install target preparation failed",
			})
		}
		_, _ = fmt.Fprintf(stderr, "failed to create install target root: %v\n", err)
		return 1
	}

	skillName := filepath.Base(filepath.Clean(skillRoot))
	installedPath, installResult, err := installSkillAtomic(skillRoot, targetRoot, skillName, report)
	if err != nil {
		if jsonOutput {
			return writeInstallJSONError(stdout, stderr, installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeWriteFailed,
				Message:       err.Error(),
				Source:        installSource,
				Target:        parsed.Target,
				PolicyProfile: parsed.Profile,
				Note:          "install write step failed",
			})
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	report.Installed = true
	report.InstalledPath = installedPath
	if jsonOutput {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render install report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
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
			i++
		case strings.HasPrefix(arg, "--profile="):
			out.Profile = strings.TrimPrefix(arg, "--profile=")
		case arg == "--format":
			if i+1 >= len(args) {
				return installArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
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
	if out.Format != "human" && out.Format != "json" {
		return installArgs{}, fmt.Errorf("unsupported install format: %s", out.Format)
	}
	return out, nil
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

func evaluateSkill(skillRoot string) ([]inspectFinding, string, error) {
	scanFindings, err := scan.ScanSkillRoot(skillRoot)
	if err != nil {
		return nil, "", err
	}

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
	return findings, decision, nil
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
		if !provenanceMatches(existingLock, stagedLock) {
			return "", "", fmt.Errorf("install target already contains skill from different provenance: %s", finalPath)
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
			return fmt.Errorf("install source contains symlink: %s", rel)
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
		written, err := copyFileWithMode(path, destPath, 0o644, maxCopyBytes)
		if err != nil {
			return err
		}
		totalBytes += written
		return nil
	})
}

func copyFileWithMode(src string, dst string, mode os.FileMode, maxBytes int64) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("failed to open source file: %w", err)
	}
	defer in.Close()

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
			Profile:  report.PolicyProfile,
			Decision: strings.ToLower(report.Decision),
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
		sum, size, err := hashFile(path)
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

func hashFile(path string) (sum string, size int64, err error) {
	return hashFileWithLimit(path, installMaxDigestFileBytes)
}

func hashFileWithLimit(path string, maxBytes int64) (sum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer f.Close()

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

	var lock installLock
	if err := json.Unmarshal(raw.Bytes(), &lock); err != nil {
		return installLock{}, fmt.Errorf("invalid install lockfile JSON: %s", path)
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
