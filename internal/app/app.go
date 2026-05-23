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

	"github.com/watany-dev/gokui/internal/limitio"
	"github.com/watany-dev/gokui/internal/materialize"
	"github.com/watany-dev/gokui/internal/scan"
	srcpkg "github.com/watany-dev/gokui/internal/source"
	yaml "go.yaml.in/yaml/v4"
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

type inspectSARIFReport struct {
	Version string            `json:"version"`
	Schema  string            `json:"$schema"`
	Runs    []inspectSARIFRun `json:"runs"`
}

type inspectSARIFRun struct {
	Tool        inspectSARIFTool         `json:"tool"`
	Results     []inspectSARIFResult     `json:"results"`
	Invocations []inspectSARIFInvocation `json:"invocations,omitempty"`
	Properties  inspectSARIFProperties   `json:"properties"`
}

type inspectSARIFTool struct {
	Driver inspectSARIFDriver `json:"driver"`
}

type inspectSARIFDriver struct {
	Name    string             `json:"name"`
	Version string             `json:"version"`
	Rules   []inspectSARIFRule `json:"rules,omitempty"`
}

type inspectSARIFRule struct {
	ID               string                       `json:"id"`
	ShortDescription inspectSARIFMessageContainer `json:"shortDescription"`
}

type inspectSARIFMessageContainer struct {
	Text string `json:"text"`
}

type inspectSARIFResult struct {
	RuleID    string                       `json:"ruleId"`
	Level     string                       `json:"level"`
	Message   inspectSARIFMessageContainer `json:"message"`
	Locations []inspectSARIFLocation       `json:"locations,omitempty"`
}

type inspectSARIFLocation struct {
	PhysicalLocation inspectSARIFPhysicalLocation `json:"physicalLocation"`
}

type inspectSARIFPhysicalLocation struct {
	ArtifactLocation inspectSARIFArtifactLocation `json:"artifactLocation"`
	Region           *inspectSARIFRegion          `json:"region,omitempty"`
}

type inspectSARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type inspectSARIFRegion struct {
	StartLine int `json:"startLine"`
}

type inspectSARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type inspectSARIFProperties struct {
	SchemaVersion string `json:"schema_version"`
	PreRelease    bool   `json:"pre_release"`
	SourceInput   string `json:"source_input"`
	SourceKind    string `json:"source_kind"`
	Decision      string `json:"decision"`
	Note          string `json:"note"`
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

type skillFrontmatter struct {
	Name        string
	Description string
}

var (
	skillNamePattern                 = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	descriptionURLPattern            = regexp.MustCompile(`(?i)\b(?:https?://|ftp://|www\.)\S+`)
	descriptionCommandPattern        = regexp.MustCompile(`(?i)\b(run|execute|exec|invoke|call|use)\b.{0,30}\b(bash|sh|zsh|pwsh|powershell|python|node|npm|npx|uvx|go|curl|wget|terminal|command)\b`)
	descriptionOverridePattern       = regexp.MustCompile(`(?i)\b(ignore|override|bypass)\b.{0,40}\b(previous|prior|system|higher|earlier)\b.{0,20}\b(instruction|instructions|prompt|prompts)\b`)
	ruleIDPrefixPattern              = regexp.MustCompile(`^([A-Z][A-Z0-9_]+):\s`)
	ruleIDAnywherePattern            = regexp.MustCompile(`(?:^|[^A-Z0-9_])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+):\s`)
	errorCodePattern                 = regexp.MustCompile(`^[A-Z0-9_]+$`)
	maxSkillFrontmatterBytes   int64 = 1_000_000
	errInspectSourceNotFound         = errors.New("inspect source not found")
)

const ruleSkillFrontmatterTooLarge = "SKILL_FRONTMATTER_TOO_LARGE"
const (
	ruleInspectSourceSymlink          = "INSPECT_SOURCE_SYMLINK_DETECTED"
	ruleSkillFrontmatterSymlink       = "SKILL_FRONTMATTER_SYMLINK_DETECTED"
	ruleSkillFrontmatterSpecialFile   = "SKILL_FRONTMATTER_SPECIAL_FILE"
	ruleSkillFrontmatterSourceChanged = "SKILL_FRONTMATTER_SOURCE_CHANGED_DURING_READ"
)

const (
	descriptionToolInjectionRuleID      = "DESCRIPTION_TOOL_INJECTION"
	inspectErrorCodeArgsInvalid         = "INSPECT_ARGS_INVALID"
	inspectErrorCodeSourceNotFound      = "INSPECT_SOURCE_NOT_FOUND"
	inspectErrorCodeSourceInvalid       = "INSPECT_SOURCE_INVALID"
	inspectErrorCodeSourcePrepareFailed = "INSPECT_SOURCE_PREPARE_FAILED"
	inspectErrorCodeScanFailed          = "INSPECT_SCAN_FAILED"
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
		return 1
	}

	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, BuildVersionString(cfg))
		return 0
	}

	switch args[0] {
	case "fetch":
		return runFetch(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdout, stderr)
	case "update":
		return runUpdate(args[1:], stdout, stderr)
	case "lock":
		if len(args) >= 2 && args[1] == "verify" {
			return runLockVerify(args[2:], stdout, stderr)
		}
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
		return 1
	}

	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s\n", strings.Join(args, " "), usage())
	return 1
}

func usage() string {
	return strings.TrimSpace(`
gokui is pre-release software.

usage:
  gokui version
  gokui fetch github:owner/repo//path/to/skill@commit --out <quarantine-dir> [--format human|json]
  gokui inspect <local-dir|zip|github-source> [--format human|json|sarif]
  gokui install <source> --target codex --profile strict [--format human|json]
  gokui update --dry-run [--target codex|custom:/path] [--format human|json]
  gokui lock verify [path] [--format human|json]`)
}

func runInspect(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := inspectArgsRequestJSON(args)
	input, format, err := parseInspectArgs(args)
	if err != nil {
		if requestedJSON {
			sourceArg := extractInspectSourceArg(args)
			return writeInspectJSONError(stdout, stderr, inspectErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     inspectErrorCodeArgsInvalid,
				Message:       err.Error(),
				Source: source{
					Input: sourceArg,
					Kind:  detectSourceKind(sourceArg),
				},
				Note: "inspect failed before source evaluation",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}
	jsonOutput := format == "json"

	sourceKind := detectSourceKind(input)

	if sourceKind != "github-source" {
		if _, statErr := os.Stat(input); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				if jsonOutput {
					return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
				return 1
			}
			accessErr := fmt.Sprintf("failed to access inspect source: %v", statErr)
			if jsonOutput {
				return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
			return 1
		}
	}

	findings := make([]inspectFinding, 0)
	decision := "PASS"
	note := "pre-release inspect includes structural and markdown checks"
	if sourceKind == "github-source" {
		spec, parseErr := srcpkg.ParseGitHubSource(input)
		if parseErr != nil {
			if jsonOutput {
				return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
			return 1
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			decision = "PRE_RELEASE_STUB"
			note = "github source inspect is not implemented yet (floating ref accepted for inspect-only pre-release)"
		} else {
			skillRoot, cleanup, prepErr := preparePolicyEvaluationSource(input, sourceKind)
			if cleanup != nil {
				defer cleanup()
			}
			if prepErr != nil {
				if jsonOutput {
					return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
				return 1
			}
			scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
			if scanErr != nil {
				if jsonOutput {
					return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
				return 1
			}
			findings, decision = toInspectFindings(scanFindings)
			note = "pre-release inspect includes structural and markdown checks (github commit-pinned source)"
		}
	} else {
		skillRoot, cleanup, validateErr := prepareInspectSource(input, sourceKind)
		if cleanup != nil {
			defer cleanup()
		}
		if validateErr != nil {
			if jsonOutput {
				errorCode := inspectErrorCodeSourcePrepareFailed
				if isInspectSourceNotFoundError(validateErr) {
					errorCode = inspectErrorCodeSourceNotFound
				}
				return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
			return 1
		}
		scanFindings, scanErr := scan.ScanSkillRoot(skillRoot)
		if scanErr != nil {
			if jsonOutput {
				return writeInspectJSONError(stdout, stderr, inspectErrorReport{
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
			return 1
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
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == "REJECTED" {
			return 2
		}
		return 0
	}
	if format == "sarif" {
		out, marshalErr := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect SARIF report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == "REJECTED" {
			return 2
		}
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "gokui inspect report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
	}
	if report.Decision == "REJECTED" {
		return 2
	}
	return 0
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
	if format != "human" && format != "json" && format != "sarif" {
		return "", "", fmt.Errorf("unsupported inspect format: %s", format)
	}
	return input, format, nil
}

func buildInspectSARIFReport(report inspectReport) inspectSARIFReport {
	rules := make([]inspectSARIFRule, 0)
	seen := make(map[string]struct{}, len(report.Findings))
	for _, finding := range report.Findings {
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		rules = append(rules, inspectSARIFRule{
			ID: finding.ID,
			ShortDescription: inspectSARIFMessageContainer{
				Text: finding.Summary,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	results := make([]inspectSARIFResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		result := inspectSARIFResult{
			RuleID:  finding.ID,
			Level:   inspectSeverityToSARIFLevel(finding.Severity),
			Message: inspectSARIFMessageContainer{Text: finding.Summary},
		}
		location := inspectSARIFLocation{
			PhysicalLocation: inspectSARIFPhysicalLocation{
				ArtifactLocation: inspectSARIFArtifactLocation{
					URI: finding.File,
				},
			},
		}
		if finding.Line > 0 {
			location.PhysicalLocation.Region = &inspectSARIFRegion{StartLine: finding.Line}
		}
		if finding.File != "" {
			result.Locations = []inspectSARIFLocation{location}
		}
		results = append(results, result)
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
						Rules:   rules,
					},
				},
				Results: []inspectSARIFResult(results),
				Invocations: []inspectSARIFInvocation{
					{ExecutionSuccessful: report.Decision != "REJECTED"},
				},
				Properties: inspectSARIFProperties{
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
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
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
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render inspect error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func inferRuleIDFromMessage(message string) string {
	match := ruleIDPrefixPattern.FindStringSubmatch(strings.TrimSpace(message))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func inferRuleIDForJSONError(message string) string {
	if id := inferRuleIDFromMessage(message); id != "" {
		return id
	}
	match := ruleIDAnywherePattern.FindStringSubmatch(message)
	if len(match) != 2 {
		return ""
	}
	return match[1]
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
	if err := rejectSymlinkPath(input, "inspect local source", ruleInspectSourceSymlink); err != nil {
		return err
	}
	info, lstatErr := os.Lstat(input)
	if lstatErr != nil {
		return fmt.Errorf("%w: %s", errInspectSourceNotFound, input)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: inspect local source must not be a symlink: %s", ruleInspectSourceSymlink, input)
	}
	if !info.IsDir() {
		return fmt.Errorf("inspect local source must be a directory: %s", input)
	}

	skillPath := filepath.Join(input, "SKILL.md")
	if err := rejectSymlinkPath(skillPath, "inspect local source SKILL.md", ruleSkillFrontmatterSymlink); err != nil {
		return err
	}
	skillInfo, skillErr := os.Lstat(skillPath)
	if skillErr != nil {
		return fmt.Errorf("inspect local dir must contain SKILL.md at root: %s", input)
	}
	if skillInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: inspect local source SKILL.md must not be a symlink: %s", ruleSkillFrontmatterSymlink, skillPath)
	}

	meta, err := validateSkillFrontmatter(skillPath)
	if err != nil {
		return err
	}

	dirName := filepath.Base(filepath.Clean(input))
	if dirName != meta.Name {
		return fmt.Errorf("frontmatter name must match directory name: name=%s dir=%s", meta.Name, dirName)
	}

	return nil
}

func isInspectSourceNotFoundError(err error) bool {
	return errors.Is(err, errInspectSourceNotFound)
}

func validateSkillFrontmatter(skillPath string) (skillFrontmatter, error) {
	info, statErr := os.Lstat(skillPath)
	if statErr != nil {
		return skillFrontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return skillFrontmatter{}, fmt.Errorf("%s: SKILL.md must not be a symlink: %s", ruleSkillFrontmatterSymlink, skillPath)
	}
	if !info.Mode().IsRegular() {
		return skillFrontmatter{}, fmt.Errorf("%s: SKILL.md must be a regular file: %s", ruleSkillFrontmatterSpecialFile, skillPath)
	}
	f, err := os.Open(skillPath)
	if err != nil {
		return skillFrontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	defer f.Close()
	currentInfo, statErr := f.Stat()
	if statErr != nil {
		return skillFrontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}
	if err := ensureSkillFrontmatterStableFile(info, currentInfo, skillPath); err != nil {
		return skillFrontmatter{}, err
	}
	var content bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&content, f, maxSkillFrontmatterBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return skillFrontmatter{}, fmt.Errorf("%s: SKILL.md exceeds size limit: %s", ruleSkillFrontmatterTooLarge, skillPath)
		}
		return skillFrontmatter{}, fmt.Errorf("failed to read SKILL.md: %s", skillPath)
	}

	text := strings.ReplaceAll(content.String(), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || lines[0] != "---" {
		return skillFrontmatter{}, fmt.Errorf("SKILL.md must start with YAML frontmatter: %s", skillPath)
	}

	end := -1
	for i := 1; i < len(lines); i++ {
		if lines[i] == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return skillFrontmatter{}, fmt.Errorf("SKILL.md frontmatter is not closed: %s", skillPath)
	}

	frontmatter := strings.Join(lines[1:end], "\n")
	root, err := parseFrontmatterYAML(frontmatter)
	if err != nil {
		return skillFrontmatter{}, fmt.Errorf("invalid SKILL.md frontmatter YAML: %s", skillPath)
	}

	if err := validateFrontmatterYAML(root); err != nil {
		return skillFrontmatter{}, err
	}

	if err := validateNoDuplicateKeys(root); err != nil {
		return skillFrontmatter{}, err
	}

	name, okName := frontmatterStringField(root, "name")
	description, okDescription := frontmatterStringField(root, "description")
	if !okName || !okDescription || strings.TrimSpace(name) == "" || strings.TrimSpace(description) == "" {
		return skillFrontmatter{}, fmt.Errorf("frontmatter must include non-empty string fields: name and description")
	}

	if err := validateSkillName(name); err != nil {
		return skillFrontmatter{}, err
	}
	if err := validateSkillDescription(description); err != nil {
		return skillFrontmatter{}, err
	}

	return skillFrontmatter{
		Name:        name,
		Description: description,
	}, nil
}

func ensureSkillFrontmatterStableFile(previous os.FileInfo, current os.FileInfo, skillPath string) error {
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: SKILL.md changed during read: %s", ruleSkillFrontmatterSourceChanged, skillPath)
}

func parseFrontmatterYAML(frontmatter string) (*yaml.Node, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(frontmatter))
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return nil, err
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("frontmatter root must be a YAML mapping")
	}

	return doc.Content[0], nil
}

func validateFrontmatterYAML(node *yaml.Node) error {
	if node == nil {
		return fmt.Errorf("frontmatter root must be a YAML mapping")
	}

	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are not allowed in SKILL.md frontmatter")
	}
	if node.Anchor != "" {
		return fmt.Errorf("YAML anchors are not allowed in SKILL.md frontmatter")
	}
	if isCustomYAMLTag(node.Tag) {
		return fmt.Errorf("custom YAML tags are not allowed in SKILL.md frontmatter")
	}

	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind == yaml.ScalarNode && key.Value == "<<" {
				return fmt.Errorf("YAML merge keys are not allowed in SKILL.md frontmatter")
			}
			if key.Tag == "!!merge" {
				return fmt.Errorf("YAML merge keys are not allowed in SKILL.md frontmatter")
			}
		}
	}

	for _, child := range node.Content {
		if err := validateFrontmatterYAML(child); err != nil {
			return err
		}
	}

	return nil
}

func isCustomYAMLTag(tag string) bool {
	if tag == "" {
		return false
	}
	return strings.HasPrefix(tag, "!") && !strings.HasPrefix(tag, "!!")
}

func validateNoDuplicateKeys(root *yaml.Node) error {
	seen := make(map[string]struct{}, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}

		if _, ok := seen[key.Value]; ok {
			return fmt.Errorf("duplicate frontmatter key: %s", key.Value)
		}
		seen[key.Value] = struct{}{}
	}
	return nil
}

func frontmatterStringField(root *yaml.Node, field string) (string, bool) {
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value != field {
			continue
		}
		if value.Kind != yaml.ScalarNode {
			return "", false
		}
		return value.Value, true
	}
	return "", false
}

func validateSkillName(name string) error {
	if len(name) > 64 {
		return fmt.Errorf("frontmatter name is invalid: must be at most 64 characters")
	}
	if !skillNamePattern.MatchString(name) {
		return fmt.Errorf("frontmatter name is invalid: expected lowercase ASCII letters, digits, and single hyphens")
	}
	return nil
}

func validateSkillDescription(description string) error {
	trimmed := strings.TrimSpace(description)
	if trimmed == "" {
		return fmt.Errorf("frontmatter must include non-empty string fields: name and description")
	}
	if utf8.RuneCountInString(trimmed) > 1024 {
		return fmt.Errorf("description must be 1 to 1024 characters")
	}
	if descriptionURLPattern.MatchString(trimmed) {
		return fmt.Errorf("description must not contain URLs")
	}
	if strings.Contains(trimmed, "```") {
		return fmt.Errorf("description must not contain code fences")
	}
	if descriptionOverridePattern.MatchString(trimmed) {
		return fmt.Errorf("%s: description must not contain prompt override language", descriptionToolInjectionRuleID)
	}
	if descriptionCommandPattern.MatchString(trimmed) {
		return fmt.Errorf("%s: description must not include tool or command execution instructions", descriptionToolInjectionRuleID)
	}
	return nil
}
