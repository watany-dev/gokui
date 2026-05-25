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
	"time"

	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

var updateURLPattern = regexp.MustCompile(`(?i)(?:https?://|//)[^\s<>"')\]]+`)

var (
	updateMaxURLScanFileBytes int64 = 1_000_000
	updateMaxScanFiles              = 10_000
	errUpdateTargetRead             = errors.New("failed to read update target")
)

type updateArgs struct {
	DryRun bool
	Target string
	Format string
}

type updateReport struct {
	SchemaVersion string            `json:"schema_version"`
	Target        string            `json:"target"`
	DryRun        bool              `json:"dry_run"`
	Skills        []updateSkillItem `json:"skills"`
	Summary       updateSummary     `json:"summary"`
	Note          string            `json:"note"`
}

type updateErrorReport struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code"`
	RuleID        string `json:"rule_id,omitempty"`
	Message       string `json:"message"`
	Target        string `json:"target"`
	Note          string `json:"note"`
}

type updateSkillItem struct {
	Name                 string                     `json:"name"`
	Path                 string                     `json:"path"`
	Source               source                     `json:"source"`
	Status               string                     `json:"status"`
	ErrorCode            string                     `json:"error_code"`
	RuleID               string                     `json:"rule_id,omitempty"`
	Decision             string                     `json:"decision"`
	Diff                 updateDiff                 `json:"diff"`
	Risk                 updateRisk                 `json:"risk"`
	RiskScore            updateRiskScore            `json:"risk_score"`
	NewURLs              []string                   `json:"new_urls"`
	NewExecutableFiles   []string                   `json:"new_executable_files"`
	Findings             []inspectFinding           `json:"findings"`
	SeverityOverrides    []severityOverrideAudit    `json:"severity_overrides"`
	SeverityOverrideDiff updateSeverityOverrideDiff `json:"severity_override_diff"`
	Message              string                     `json:"message"`
}

type updateSeverityOverrideDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

const (
	updateCodeUpToDate           = "UP_TO_DATE"
	updateCodeChanged            = "SOURCE_CHANGED"
	updateCodePolicyRejected     = "POLICY_REJECTED"
	updateCodeGitHubRefFloating  = "GITHUB_REF_NOT_PINNED"
	updateCodeLockfileInvalid    = "LOCKFILE_INVALID"
	updateCodeGitHubSourceBad    = "GITHUB_SOURCE_INVALID"
	updateCodeSourceMetadataBad  = "SOURCE_METADATA_INVALID"
	updateCodeSourcePrepareError = "SOURCE_PREPARE_FAILED"
	updateCodeEvaluationError    = "EVALUATION_ERROR"
)

const (
	updateFatalCodeArgsInvalid    = "UPDATE_ARGS_INVALID"
	updateFatalCodeTargetInvalid  = "UPDATE_TARGET_INVALID"
	updateFatalCodeTargetReadFail = "UPDATE_TARGET_READ_FAILED"
	updateFatalCodeReportBuild    = "UPDATE_REPORT_BUILD_FAILED"
	updateFatalCodePolicyLoadFail = "UPDATE_POLICY_LOAD_FAILED"
	updateFatalCodeUnknown        = "UPDATE_FAILED"
)

const ruleUpdateTargetSymlink = "UPDATE_TARGET_SYMLINK_DETECTED"
const ruleUpdateTargetEntrySymlink = "UPDATE_TARGET_ENTRY_SYMLINK_DETECTED"
const ruleUpdateURLScanSymlink = "UPDATE_URL_SCAN_SYMLINK_DETECTED"
const ruleUpdateURLScanSpecialFile = "UPDATE_URL_SCAN_SPECIAL_FILE"
const ruleUpdateURLScanSourceChanged = "UPDATE_URL_SCAN_SOURCE_CHANGED_DURING_READ"
const ruleUpdateExecutableScanSymlink = "UPDATE_EXECUTABLE_SCAN_SYMLINK_DETECTED"
const ruleUpdateExecutableScanSpecialFile = "UPDATE_EXECUTABLE_SCAN_SPECIAL_FILE"

type updateDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

type updateRisk struct {
	Previous lockFindingSummary `json:"previous"`
	Current  lockFindingSummary `json:"current"`
	Delta    lockFindingSummary `json:"delta"`
}

type updateRiskScore struct {
	Model    string `json:"model"`
	Previous int    `json:"previous"`
	Current  int    `json:"current"`
	Delta    int    `json:"delta"`
	Signals  int    `json:"signals"`
}

type updateRiskSignalInputs struct {
	NewURLs         int
	NewExecutables  int
	FileDelta       int
	OverrideAdded   int
	OverrideRemoved int
}

const (
	updateRiskScoreModel          = "severity-signals-v1"
	updateRiskWeightCritical      = 100
	updateRiskWeightHigh          = 25
	updateRiskWeightMedium        = 7
	updateRiskWeightLow           = 2
	updateRiskWeightNewURL        = 6
	updateRiskWeightNewExecutable = 15
	updateRiskWeightFileDelta     = 2
	updateRiskWeightOverrideAdd   = 10
	updateRiskWeightOverrideDrop  = -6
	updateRiskCapNewURL           = 60
	updateRiskCapNewExecutable    = 90
	updateRiskCapFileDelta        = 60
	updateRiskCapOverrideAdd      = 40
	updateRiskCapOverrideDrop     = 30
)

type updateSummary struct {
	Total    int `json:"total"`
	UpToDate int `json:"up_to_date"`
	Changed  int `json:"changed"`
	Rejected int `json:"rejected"`
	Errors   int `json:"errors"`
	Skipped  int `json:"skipped"`
}

func runUpdate(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := updateArgsRequestJSON(args)
	requestedSARIF := updateArgsRequestSARIF(args)

	parsed, err := parseUpdateArgs(args)
	if err != nil {
		if requestedJSON {
			return writeUpdateJSONError(stdout, stderr, updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     updateFatalCodeArgsInvalid,
				Message:       err.Error(),
				Target:        extractUpdateTargetArg(args),
				Note:          "update failed before target resolution",
			})
		}
		if requestedSARIF {
			return writeUpdateSARIFError(stdout, stderr, updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     updateFatalCodeArgsInvalid,
				Message:       err.Error(),
				Target:        extractUpdateTargetArg(args),
				Note:          "update failed before target resolution",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	targetRoot, err := resolveInstallTarget(parsed.Target)
	if err != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeTargetInvalid,
			Message:       err.Error(),
			Target:        parsed.Target,
			Note:          "update target validation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}
	if err := rejectSymlinkPath(targetRoot, "update target root", ruleUpdateTargetSymlink); err != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeTargetInvalid,
			Message:       err.Error(),
			Target:        parsed.Target,
			Note:          "update target validation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	userPolicy, policyLoaded, policyErr := loadUserPolicyConfig()
	if policyErr != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodePolicyLoadFail,
			Message:       policyErr.Error(),
			Target:        targetRoot,
			Note:          "update failed while loading policy configuration",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, policyErr.Error())
		return 1
	}

	report, err := buildUpdateReport(targetRoot, policyLoaded, userPolicy)
	if err != nil {
		errorCode := updateFatalCodeReportBuild
		if isUpdateTargetReadError(err) {
			errorCode = updateFatalCodeTargetReadFail
		}
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     errorCode,
			Message:       err.Error(),
			Target:        targetRoot,
			Note:          "update report generation failed",
		}) {
			return 1
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return 1
	}

	if parsed.Format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if parsed.Format == "sarif" {
		out, _ := json.MarshalIndent(buildUpdateSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if parsed.Format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildUpdateCompactSummary(report))
	} else {
		_, _ = fmt.Fprintln(stdout, "gokui update report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "target: %s\n", report.Target)
		_, _ = fmt.Fprintf(stdout, "skills: %d\n", report.Summary.Total)
		for _, skill := range report.Skills {
			decision := skill.Decision
			if decision == "" {
				decision = "-"
			}
			_, _ = fmt.Fprintf(stdout, "- %s: %s (decision=%s)\n", skill.Name, skill.Status, decision)
			_, _ = fmt.Fprintf(stdout, "  code: %s\n", skill.ErrorCode)
			_, _ = fmt.Fprintf(stdout, "  diff added=%d removed=%d changed=%d\n", len(skill.Diff.Added), len(skill.Diff.Removed), len(skill.Diff.Changed))
			_, _ = fmt.Fprintf(stdout, "  new urls=%d new executables=%d\n", len(skill.NewURLs), len(skill.NewExecutableFiles))
			_, _ = fmt.Fprintf(stdout, "  severity overrides active=%d added=%d removed=%d\n", len(skill.SeverityOverrides), len(skill.SeverityOverrideDiff.Added), len(skill.SeverityOverrideDiff.Removed))
			_, _ = fmt.Fprintf(stdout, "  note: %s\n", skill.Message)
		}
		_, _ = fmt.Fprintf(stdout, "summary: up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d\n",
			report.Summary.UpToDate,
			report.Summary.Changed,
			report.Summary.Rejected,
			report.Summary.Skipped,
			report.Summary.Errors,
		)
	}

	if report.Summary.Errors > 0 {
		return 1
	}
	if report.Summary.Rejected > 0 {
		return 2
	}
	return 0
}

func updateArgsRequestJSON(args []string) bool {
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

func updateArgsRequestSARIF(args []string) bool {
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

func extractUpdateTargetArg(args []string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--target" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], "--target=") {
			return strings.TrimPrefix(args[i], "--target=")
		}
	}
	return "codex"
}

func writeUpdateJSONError(stdout io.Writer, stderr io.Writer, report updateErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, updateFatalCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render update error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func writeUpdateSARIFError(stdout io.Writer, stderr io.Writer, report updateErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, updateFatalCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(buildUpdateSARIFErrorReport(report), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render update sarif error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func buildUpdateSARIFErrorReport(report updateErrorReport) inspectSARIFReport {
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
					SourceInput:   report.Target,
					SourceKind:    "update-target",
					Decision:      report.Status,
					Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
				},
			},
		},
	}
}

func emitUpdateStructuredError(format string, stdout io.Writer, stderr io.Writer, report updateErrorReport) bool {
	switch format {
	case "json":
		_ = writeUpdateJSONError(stdout, stderr, report)
		return true
	case "sarif":
		_ = writeUpdateSARIFError(stdout, stderr, report)
		return true
	default:
		return false
	}
}

func parseUpdateArgs(args []string) (updateArgs, error) {
	out := updateArgs{
		Target: "codex",
		Format: "human",
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--dry-run":
			out.DryRun = true
		case arg == "--target":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --target")
			}
			out.Target = args[i+1]
			i++
		case strings.HasPrefix(arg, "--target="):
			out.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--format":
			if i+1 >= len(args) {
				return updateArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return updateArgs{}, fmt.Errorf("unknown update option: %s", arg)
		default:
			return updateArgs{}, fmt.Errorf("update does not accept positional arguments: %s", arg)
		}
	}

	if !out.DryRun {
		return updateArgs{}, fmt.Errorf("update currently requires --dry-run")
	}
	if out.Format != "human" && out.Format != "json" && out.Format != "sarif" && out.Format != "compact" {
		return updateArgs{}, fmt.Errorf("unsupported update format: %s", out.Format)
	}
	return out, nil
}

func buildUpdateSARIFReport(report updateReport) inspectSARIFReport {
	decision := "PASS"
	if report.Summary.Errors > 0 {
		decision = "ERROR"
	} else if report.Summary.Rejected > 0 {
		decision = "REJECTED"
	} else if report.Summary.Changed > 0 {
		decision = "CHANGED"
	}

	findings := make([]inspectFinding, 0, 64)
	for _, skill := range report.Skills {
		if len(skill.Findings) > 0 {
			for _, finding := range skill.Findings {
				filePath := finding.File
				if filePath != "" {
					filePath = filepath.ToSlash(filepath.Join(skill.Name, filePath))
				}
				summary := finding.Summary
				if strings.TrimSpace(summary) == "" {
					summary = fmt.Sprintf("%s finding in %s", finding.ID, skill.Name)
				}
				findings = append(findings, inspectFinding{
					ID:       finding.ID,
					Severity: finding.Severity,
					File:     filePath,
					Line:     finding.Line,
					Summary:  summary,
				})
			}
			continue
		}
		if skill.Status != "ERROR" && skill.Status != "REJECTED" {
			continue
		}
		ruleID := skill.RuleID
		if ruleID == "" {
			ruleID = skill.ErrorCode
		}
		if ruleID == "" {
			ruleID = "UPDATE_SKILL_STATUS"
		}
		summary := skill.Message
		if strings.TrimSpace(summary) == "" {
			summary = fmt.Sprintf("%s: %s", skill.Status, skill.Name)
		}
		findings = append(findings, inspectFinding{
			ID:       ruleID,
			Severity: "high",
			File:     filepath.ToSlash(skill.Name),
			Line:     1,
			Summary:  summary,
		})
	}

	inspectEquivalent := inspectReport{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		Source: source{
			Input: report.Target,
			Kind:  "update-target",
		},
		Decision: decision,
		Findings: findings,
		Note:     report.Note,
	}
	sarif := buildInspectSARIFReport(inspectEquivalent)
	if len(sarif.Runs) > 0 {
		sarif.Runs[0].Invocations = []inspectSARIFInvocation{
			{ExecutionSuccessful: report.Summary.Errors == 0 && report.Summary.Rejected == 0},
		}
	}
	return sarif
}

func buildUpdateCompactSummary(report updateReport) string {
	return fmt.Sprintf(
		"update total=%d up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d target=%q",
		report.Summary.Total,
		report.Summary.UpToDate,
		report.Summary.Changed,
		report.Summary.Rejected,
		report.Summary.Skipped,
		report.Summary.Errors,
		report.Target,
	)
}

func buildUpdateReport(targetRoot string, policyLoaded bool, cfg policypkg.Config) (updateReport, error) {
	cleanTarget := filepath.Clean(targetRoot)
	entries, err := os.ReadDir(cleanTarget)
	if err != nil {
		return updateReport{}, fmt.Errorf("%w: %s", errUpdateTargetRead, cleanTarget)
	}

	skills := make([]updateSkillItem, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return updateReport{}, fmt.Errorf("%s: update target entry must not be a symlink: %s", ruleUpdateTargetEntrySymlink, filepath.Join(cleanTarget, entry.Name()))
		}
		if !entry.IsDir() {
			continue
		}
		skillPath := filepath.Join(cleanTarget, entry.Name())
		item := updateSkillItem{
			Name:      entry.Name(),
			Path:      skillPath,
			ErrorCode: updateCodeEvaluationError,
			Diff: updateDiff{
				Added:   []string{},
				Removed: []string{},
				Changed: []string{},
			},
			NewURLs:            []string{},
			NewExecutableFiles: []string{},
			Findings:           []inspectFinding{},
			RiskScore:          zeroUpdateRiskScore(),
			SeverityOverrides:  []severityOverrideAudit{},
			SeverityOverrideDiff: updateSeverityOverrideDiff{
				Added:   []string{},
				Removed: []string{},
			},
		}
		lockPath := filepath.Join(skillPath, installLockFile)
		lock, err := readInstallLock(lockPath)
		if err != nil {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeLockfileInvalid
			item.Message = "missing or invalid lockfile"
			item.RuleID = inferRuleIDForJSONError(item.Message)
			skills = append(skills, item)
			continue
		}
		item.Source = source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		}
		item.SeverityOverrides = cloneSeverityOverrides(lock.Policy.SeverityOverrides)

		enriched, err := evaluateUpdateSkill(item, lock, policyLoaded, cfg)
		if err != nil {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeEvaluationError
			item.Message = err.Error()
			item.RuleID = inferRuleIDForJSONError(item.Message)
			skills = append(skills, item)
			continue
		}
		skills = append(skills, enriched)
	}

	sort.Slice(skills, func(i, j int) bool {
		return skills[i].Name < skills[j].Name
	})

	summary := summarizeUpdateSkills(skills)
	return updateReport{
		SchemaVersion: reportSchemaVersion,
		Target:        cleanTarget,
		DryRun:        true,
		Skills:        skills,
		Summary:       summary,
		Note:          "pre-release update performs dry-run diff and policy re-evaluation",
	}, nil
}

func isUpdateTargetReadError(err error) bool {
	return errors.Is(err, errUpdateTargetRead)
}

func evaluateUpdateSkill(item updateSkillItem, lock installLock, policyLoaded bool, cfg policypkg.Config) (updateSkillItem, error) {
	item.RiskScore = computeUpdateRiskScore(lock.Findings, lock.Findings, updateRiskSignalInputs{})
	if err := validateUpdateLockEnvelope(lock, item.Name); err != nil {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = err.Error()
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	policyProfileRaw := lock.Policy.Profile
	policyProfile := normalizePolicyProfile(policyProfileRaw)
	if policyProfileRaw != policyProfile {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock policy profile must be canonical lowercase without surrounding whitespace"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if !isSupportedPolicyProfile(policyProfile) {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = fmt.Sprintf("unsupported policy profile in lockfile: %s", policyProfileRaw)
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	policyDecisionRaw := lock.Policy.Decision
	if policyDecisionRaw != "pass" {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock policy decision must be canonical lowercase pass"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	sourceInputRaw := lock.Source.Input
	sourceInput := strings.TrimSpace(sourceInputRaw)
	if sourceInput == "" {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source input is empty"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if sourceInputRaw != sourceInput {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source input must not contain leading or trailing whitespace"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}

	kindRaw := lock.Source.Kind
	kind := strings.TrimSpace(kindRaw)
	detectedKind := detectSourceKind(sourceInput)
	if kind == "" {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source kind is empty"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if kindRaw != kind {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source kind must not contain leading or trailing whitespace"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if kind != strings.ToLower(kind) {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source kind must be canonical lowercase"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	expectedType := sourceTypeFromKind(kind)
	if expectedType == "unknown" {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = fmt.Sprintf("unsupported source kind in lockfile: %s", kind)
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if expectedType != "github" {
		cleanedInput := filepath.Clean(sourceInput)
		if sourceInput != cleanedInput {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeLockfileInvalid
			item.Message = "lock source input must be a canonical cleaned path for local/archive sources"
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
	}
	if kind != detectedKind {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeSourceMetadataBad
		item.Message = fmt.Sprintf("lock source kind does not match source input: kind=%s detected=%s", kind, detectedKind)
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	sourceTypeRaw := lock.Source.Type
	sourceType := strings.TrimSpace(sourceTypeRaw)
	if sourceTypeRaw != sourceType {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source type must not contain leading or trailing whitespace"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if sourceType != strings.ToLower(sourceType) {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = "lock source type must be canonical lowercase"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if sourceType != expectedType {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = fmt.Sprintf("source type mismatch for kind %s: expected %s, got %s", kind, expectedType, sourceType)
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if kind == "github-source" {
		spec, parseErr := srcpkg.ParseGitHubSource(sourceInput)
		if parseErr != nil {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeGitHubSourceBad
			item.Message = fmt.Sprintf("invalid github source in lockfile: %v", parseErr)
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if sourceInput != canonicalGitHubSourceInput(spec) {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeLockfileInvalid
			item.Message = "github lock source input must be canonical"
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			item.Status = "REJECTED"
			item.ErrorCode = updateCodeGitHubRefFloating
			item.Message = "floating github refs are not eligible for update; commit-pinned ref required"
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if err := verifyInstalledSourceMetadata(item.Path, source{
			Input: sourceInput,
			Kind:  kind,
		}); err != nil {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeSourceMetadataBad
			item.Message = err.Error()
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
	}
	if err := validateUpdateLockSkillSnapshot(lock); err != nil {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = err.Error()
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}
	if err := validateUpdateLockAgainstInstallReport(item.Path, lock); err != nil {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeLockfileInvalid
		item.Message = err.Error()
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}

	skillRoot, cleanup, err := preparePolicyEvaluationSource(sourceInput, kind)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		message := err.Error()
		status, code := classifyUpdateSourcePrepareFailure(kind, err)
		item.Status = status
		item.ErrorCode = code
		item.Message = message
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}

	effectivePolicy := cfg
	effectivePolicyLoaded := policyLoaded
	if shouldApplyRepositoryPolicy(kind) {
		repoPolicy, repoPolicyFound, repoPolicyErr := loadRepositoryPolicyConfig(skillRoot)
		if repoPolicyErr != nil {
			item.Status = "ERROR"
			item.ErrorCode = updateCodeEvaluationError
			item.Message = repoPolicyErr.Error()
			item.RuleID = inferRuleIDForJSONError(item.Message)
			item.Risk = updateRisk{
				Previous: lock.Findings,
				Current:  lock.Findings,
			}
			return item, nil
		}
		if repoPolicyFound {
			effectivePolicy = repoPolicy
			effectivePolicyLoaded = true
		}
	}

	rejectSet, err := effectiveRejectSeveritySetForProfile(policyProfile, effectivePolicyLoaded, effectivePolicy)
	if err != nil {
		item.Status = "ERROR"
		item.ErrorCode = updateCodeEvaluationError
		item.Message = err.Error()
		item.RuleID = inferRuleIDForJSONError(item.Message)
		item.Risk = updateRisk{
			Previous: lock.Findings,
			Current:  lock.Findings,
		}
		return item, nil
	}

	findings, _, _, err := evaluateSkillWithOverrides(skillRoot, policyProfile, nil, rejectSet)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.Findings = findings

	configuredByRule := make(map[string]severityOverrideAudit, len(lock.Policy.SeverityOverrides))
	for _, override := range lock.Policy.SeverityOverrides {
		if _, exists := configuredByRule[override.RuleID]; exists {
			continue
		}
		configuredByRule[override.RuleID] = override
	}
	activeByRule := make(map[string]severityOverrideAudit, len(configuredByRule))
	decision := "PASS"
	for _, finding := range findings {
		effectiveSeverity := finding.Severity
		if override, ok := configuredByRule[finding.ID]; ok {
			if finding.Severity == "high" {
				effectiveSeverity = "medium"
			}
			activeByRule[finding.ID] = override
		}
		if _, shouldReject := rejectSet[strings.ToLower(strings.TrimSpace(effectiveSeverity))]; shouldReject {
			decision = "REJECTED"
		}
	}
	item.Decision = decision
	item.SeverityOverrides = sortSeverityOverrides(mapValuesSeverityOverrides(activeByRule))
	previousOverrideIDs := mapKeysSortedSeverityOverrideAudit(configuredByRule)
	currentOverrideIDs := mapKeysSortedSeverityOverrideAudit(activeByRule)
	item.SeverityOverrideDiff = updateSeverityOverrideDiff{
		Added:   setDiff(currentOverrideIDs, previousOverrideIDs),
		Removed: setDiff(previousOverrideIDs, currentOverrideIDs),
	}

	excludeMeta := map[string]struct{}{
		installReportFile: {},
		installLockFile:   {},
	}
	currentFiles, _, err := buildFileDigestsFiltered(skillRoot, excludeMeta)
	if err != nil {
		return updateSkillItem{}, err
	}
	previousFiles := filterLockFiles(lock.Skill.Files, excludeMeta)
	missing, changed, unexpected := diffLockFiles(previousFiles, currentFiles)
	item.Diff = updateDiff{
		Added:   unexpected,
		Removed: missing,
		Changed: changed,
	}

	previousURLs, err := collectURLs(item.Path)
	if err != nil {
		return updateSkillItem{}, err
	}
	currentURLs, err := collectURLs(skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.NewURLs = setDiff(currentURLs, previousURLs)

	previousExec, err := collectExecutableFiles(item.Path)
	if err != nil {
		return updateSkillItem{}, err
	}
	currentExec, err := collectExecutableFiles(skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.NewExecutableFiles = setDiff(currentExec, previousExec)

	currentRisk := summarizeFindingSeverities(findings)
	signals := updateRiskSignalInputs{
		NewURLs:         len(item.NewURLs),
		NewExecutables:  len(item.NewExecutableFiles),
		FileDelta:       len(item.Diff.Added) + len(item.Diff.Removed) + len(item.Diff.Changed),
		OverrideAdded:   len(item.SeverityOverrideDiff.Added),
		OverrideRemoved: len(item.SeverityOverrideDiff.Removed),
	}
	item.RiskScore = computeUpdateRiskScore(lock.Findings, currentRisk, signals)
	item.Risk = updateRisk{
		Previous: lock.Findings,
		Current:  currentRisk,
		Delta: lockFindingSummary{
			Critical: currentRisk.Critical - lock.Findings.Critical,
			High:     currentRisk.High - lock.Findings.High,
			Medium:   currentRisk.Medium - lock.Findings.Medium,
			Low:      currentRisk.Low - lock.Findings.Low,
		},
	}

	if decision == "REJECTED" {
		item.Status = "REJECTED"
		item.ErrorCode = updateCodePolicyRejected
		item.Message = "fresh policy evaluation rejected update source"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		return item, nil
	}

	changedContent := len(item.Diff.Added) > 0 || len(item.Diff.Removed) > 0 || len(item.Diff.Changed) > 0
	changedRisk := item.Risk.Delta.Critical != 0 || item.Risk.Delta.High != 0 || item.Risk.Delta.Medium != 0 || item.Risk.Delta.Low != 0
	changedSignals := len(item.NewURLs) > 0 || len(item.NewExecutableFiles) > 0
	changedOverrides := len(item.SeverityOverrideDiff.Added) > 0 || len(item.SeverityOverrideDiff.Removed) > 0
	if changedContent || changedRisk || changedSignals || changedOverrides {
		item.Status = "CHANGED"
		item.ErrorCode = updateCodeChanged
		item.Message = "update source differs from installed lock snapshot"
		item.RuleID = inferRuleIDForJSONError(item.Message)
		return item, nil
	}

	item.Status = "UP_TO_DATE"
	item.ErrorCode = updateCodeUpToDate
	item.Message = "no change detected against installed lock snapshot"
	item.RuleID = inferRuleIDForJSONError(item.Message)
	return item, nil
}

func classifyUpdateSourcePrepareFailure(kind string, err error) (status string, code string) {
	status = "ERROR"
	code = updateCodeSourcePrepareError
	if kind == "github-source" && isGitHubRefNotPinnedError(err) {
		return "REJECTED", updateCodeGitHubRefFloating
	}
	return status, code
}

func validateUpdateLockEnvelope(lock installLock, expectedSkillName string) error {
	if lock.Schema != lockSchemaVersion {
		return fmt.Errorf("unsupported lock schema: %s", lock.Schema)
	}
	trimmedName := strings.TrimSpace(lock.Name)
	if trimmedName == "" {
		return fmt.Errorf("lock name is empty")
	}
	if trimmedName != lock.Name {
		return fmt.Errorf("lock name must not contain leading or trailing whitespace")
	}
	if expectedSkillName != "" && lock.Name != expectedSkillName {
		return fmt.Errorf("lock name does not match installed skill directory: lock=%s dir=%s", lock.Name, expectedSkillName)
	}

	trimmedInstalledAt := strings.TrimSpace(lock.InstalledAt)
	if trimmedInstalledAt == "" {
		return fmt.Errorf("lock installed_at is empty")
	}
	if trimmedInstalledAt != lock.InstalledAt {
		return fmt.Errorf("lock installed_at must not contain leading or trailing whitespace")
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return fmt.Errorf("lock installed_at must be RFC3339")
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return fmt.Errorf("lock findings summary is invalid: %v", err)
	}
	if err := validateSeverityOverrideAudit(lock.Policy.SeverityOverrides); err != nil {
		return fmt.Errorf("lock policy severity_overrides is invalid: %v", err)
	}
	return nil
}

func validateUpdateLockAgainstInstallReport(skillPath string, lock installLock) error {
	reportPath := filepath.Join(skillPath, installReportFile)
	_, statErr := os.Lstat(reportPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil
		}
		return fmt.Errorf("failed to evaluate install report for update baseline: %w", statErr)
	}
	ok, detail := verifyInstallReport(skillPath, lock)
	if !ok {
		return fmt.Errorf("install report does not match lock baseline: %s", detail)
	}
	return nil
}

func validateUpdateLockSkillSnapshot(lock installLock) error {
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

func filterLockFiles(files []lockFileHash, exclude map[string]struct{}) []lockFileHash {
	out := make([]lockFileHash, 0, len(files))
	for _, file := range files {
		if _, skip := exclude[file.Path]; skip {
			continue
		}
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	return out
}

func summarizeFindingSeverities(findings []inspectFinding) lockFindingSummary {
	out := lockFindingSummary{}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			out.Critical++
		case "high":
			out.High++
		case "medium":
			out.Medium++
		case "low":
			out.Low++
		}
	}
	return out
}

func summarizeUpdateSkills(skills []updateSkillItem) updateSummary {
	out := updateSummary{Total: len(skills)}
	for _, skill := range skills {
		switch skill.Status {
		case "UP_TO_DATE":
			out.UpToDate++
		case "CHANGED":
			out.Changed++
		case "REJECTED":
			out.Rejected++
		case "SKIPPED":
			out.Skipped++
		default:
			out.Errors++
		}
	}
	return out
}

func zeroUpdateRiskScore() updateRiskScore {
	return updateRiskScore{Model: updateRiskScoreModel}
}

func computeUpdateRiskScore(previous lockFindingSummary, current lockFindingSummary, signals updateRiskSignalInputs) updateRiskScore {
	previousSeverityScore := severityWeightedScore(previous)
	currentSeverityScore := severityWeightedScore(current)
	signalScore := updateSignalScore(signals)
	currentScore := currentSeverityScore + signalScore
	return updateRiskScore{
		Model:    updateRiskScoreModel,
		Previous: previousSeverityScore,
		Current:  currentScore,
		Delta:    currentScore - previousSeverityScore,
		Signals:  signalScore,
	}
}

func severityWeightedScore(summary lockFindingSummary) int {
	return (summary.Critical * updateRiskWeightCritical) +
		(summary.High * updateRiskWeightHigh) +
		(summary.Medium * updateRiskWeightMedium) +
		(summary.Low * updateRiskWeightLow)
}

func updateSignalScore(in updateRiskSignalInputs) int {
	score := 0
	score += cappedWeightedContribution(in.NewURLs, updateRiskWeightNewURL, updateRiskCapNewURL)
	score += cappedWeightedContribution(in.NewExecutables, updateRiskWeightNewExecutable, updateRiskCapNewExecutable)
	score += cappedWeightedContribution(in.FileDelta, updateRiskWeightFileDelta, updateRiskCapFileDelta)
	score += cappedWeightedContribution(in.OverrideAdded, updateRiskWeightOverrideAdd, updateRiskCapOverrideAdd)
	score += cappedWeightedContribution(in.OverrideRemoved, updateRiskWeightOverrideDrop, updateRiskCapOverrideDrop)
	return score
}

func cappedWeightedContribution(count int, weight int, absCap int) int {
	if count <= 0 || weight == 0 {
		return 0
	}
	score := count * weight
	if absCap <= 0 {
		return score
	}
	if score > absCap {
		return absCap
	}
	if score < -absCap {
		return -absCap
	}
	return score
}

func collectURLs(root string) ([]string, error) {
	if err := ensureUpdateScanRoot(root, "URL scan", ruleUpdateURLScanSymlink, ruleUpdateURLScanSpecialFile); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 32)
	scannedFiles := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !isMarkdownLikeFile(d.Name()) {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: URL scan input contains symlink: %s", ruleUpdateURLScanSymlink, path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file for URL scan: %w", err)
		}
		if err := ensureURLScanRegularFile(info, path, root); err != nil {
			return err
		}
		previousInfo := info
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to read file for URL scan: %w", err)
		}
		defer f.Close()
		info, err = f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file for URL scan: %w", err)
		}
		if err := ensureURLScanRegularFile(info, path, root); err != nil {
			return err
		}
		if err := ensureURLScanStableFile(previousInfo, info, path, root); err != nil {
			return err
		}
		scannedFiles++
		if scannedFiles > updateMaxScanFiles {
			return fmt.Errorf("URL scan exceeded max file count: %d", updateMaxScanFiles)
		}
		content, err := readURLScanContent(f, path, root)
		if err != nil {
			return err
		}
		matches := updateURLPattern.FindAllString(content, -1)
		for _, m := range matches {
			set[m] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func ensureURLScanRegularFile(info os.FileInfo, path string, root string) error {
	if info.Mode().IsRegular() {
		return nil
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr == nil {
		path = filepath.ToSlash(rel)
	}
	return fmt.Errorf("%s: URL scan input contains non-regular file: %s", ruleUpdateURLScanSpecialFile, path)
}

func ensureURLScanStableFile(previous os.FileInfo, current os.FileInfo, path string, root string) error {
	if os.SameFile(previous, current) {
		return nil
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr == nil {
		path = filepath.ToSlash(rel)
	}
	return fmt.Errorf("%s: URL scan source changed during read: %s", ruleUpdateURLScanSourceChanged, path)
}

func collectExecutableFiles(root string) ([]string, error) {
	if err := ensureUpdateScanRoot(root, "executable scan", ruleUpdateExecutableScanSymlink, ruleUpdateExecutableScanSpecialFile); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 16)
	scannedFiles := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: executable scan input contains symlink: %s", ruleUpdateExecutableScanSymlink, path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: executable scan input contains non-regular file: %s", ruleUpdateExecutableScanSpecialFile, path)
		}
		scannedFiles++
		if scannedFiles > updateMaxScanFiles {
			return fmt.Errorf("executable scan exceeded max file count: %d", updateMaxScanFiles)
		}
		if info.Mode().Perm()&0o111 == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		set[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func readURLScanContent(r io.Reader, path string, root string) (string, error) {
	var content bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&content, r, updateMaxURLScanFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return "", fmt.Errorf("markdown file exceeds URL scan size limit: %s", path)
		}
		return "", fmt.Errorf("failed to read file for URL scan: %w", err)
	}
	return content.String(), nil
}

func ensureUpdateScanRoot(root string, label string, symlinkRuleID string, specialRuleID string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("failed to stat %s root: %w", label, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %s root must not be a symlink: %s", symlinkRuleID, label, root)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("%s: %s root must be a directory: %s", specialRuleID, label, root)
	}
	return nil
}

func mapKeysSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mapValuesSeverityOverrides(in map[string]severityOverrideAudit) []severityOverrideAudit {
	out := make([]severityOverrideAudit, 0, len(in))
	for _, override := range in {
		out = append(out, override)
	}
	return out
}

func sortSeverityOverrides(in []severityOverrideAudit) []severityOverrideAudit {
	out := cloneSeverityOverrides(in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].AppliedAt != out[j].AppliedAt {
			return out[i].AppliedAt < out[j].AppliedAt
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func mapKeysSortedSeverityOverrideAudit(in map[string]severityOverrideAudit) []string {
	keys := make([]string, 0, len(in))
	for ruleID := range in {
		keys = append(keys, ruleID)
	}
	sort.Strings(keys)
	return keys
}

func setDiff(current []string, previous []string) []string {
	previousSet := make(map[string]struct{}, len(previous))
	for _, v := range previous {
		previousSet[v] = struct{}{}
	}
	out := make([]string, 0, len(current))
	for _, v := range current {
		if _, ok := previousSet[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func isMarkdownLikeFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".md") ||
		strings.HasSuffix(lower, ".markdown") ||
		strings.HasSuffix(lower, ".txt")
}
