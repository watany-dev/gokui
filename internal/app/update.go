package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

var (
	errUpdateTargetRead = errors.New("failed to read update target")
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

type updateDeps struct {
	LoadUserPolicy          func() (policypkg.Config, bool, error)
	LoadRepositoryPolicy    func(string) (policypkg.Config, bool, error)
	PrepareEvaluationSource func(input string, sourceKind string) (string, func(), error)
}

func defaultUpdateDeps() updateDeps {
	return updateDeps{
		LoadUserPolicy:          policypkg.LoadUserPolicy,
		LoadRepositoryPolicy:    policypkg.LoadRepositoryPolicy,
		PrepareEvaluationSource: preparePolicyEvaluationSource,
	}
}

func runUpdate(args []string, stdout io.Writer, stderr io.Writer) int {
	return runUpdateWithDeps(args, stdout, stderr, defaultUpdateDeps())
}

func runUpdateWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps updateDeps) int {
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	deps = normalizeUpdateDeps(deps)

	parsed, err := parseUpdateArgs(args)
	if err != nil {
		if requestedJSON {
			return writeUpdateJSONError(stdout, stderr, updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     updateFatalCodeArgsInvalid,
				Message:       err.Error(),
				Target:        extractUpdateTargetArg(args),
				Note:          "update failed before target resolution",
			})
		}
		if requestedSARIF {
			return writeUpdateSARIFError(stdout, stderr, updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        reportStatusError,
				ErrorCode:     updateFatalCodeArgsInvalid,
				Message:       err.Error(),
				Target:        extractUpdateTargetArg(args),
				Note:          "update failed before target resolution",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}

	targetRoot, err := resolveInstallTarget(parsed.Target)
	if err != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     updateFatalCodeTargetInvalid,
			Message:       err.Error(),
			Target:        parsed.Target,
			Note:          "update target validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	if err := rejectSymlinkPath(targetRoot, "update target root", rulepkg.UpdateTargetSymlink.ID); err != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     updateFatalCodeTargetInvalid,
			Message:       err.Error(),
			Target:        parsed.Target,
			Note:          "update target validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	userPolicy, policyLoaded, policyErr := deps.LoadUserPolicy()
	if policyErr != nil {
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     updateFatalCodePolicyLoadFail,
			Message:       policyErr.Error(),
			Target:        targetRoot,
			Note:          "update failed while loading policy configuration",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, policyErr.Error())
		return exitcode.Error.Int()
	}

	report, err := buildUpdateReportWithDeps(targetRoot, policyLoaded, userPolicy, deps)
	if err != nil {
		errorCode := updateFatalCodeReportBuild
		if isUpdateTargetReadError(err) {
			errorCode = updateFatalCodeTargetReadFail
		}
		if emitUpdateStructuredError(parsed.Format, stdout, stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     errorCode,
			Message:       err.Error(),
			Target:        targetRoot,
			Note:          "update report generation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
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
		return exitcode.Error.Int()
	}
	if report.Summary.Rejected > 0 {
		return exitcode.Rejected.Int()
	}
	return exitcode.OK.Int()
}

func evaluateUpdateSkillWithDeps(item updateSkillItem, lock installLock, policyLoaded bool, cfg policypkg.Config, deps updateDeps) (updateSkillItem, error) {
	deps = normalizeUpdateDeps(deps)
	item.RiskScore = computeUpdateRiskScore(lock.Findings, lock.Findings, updateRiskSignalInputs{})
	inputs, validationErr := validateUpdateLockForEvaluation(item, lock)
	if validationErr != nil {
		return failUpdateSkillItem(item, lock, validationErr.status, validationErr.code, validationErr.message), nil
	}

	skillRoot, cleanup, err := deps.PrepareEvaluationSource(inputs.sourceInput, inputs.kind)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		message := err.Error()
		status, code := classifyUpdateSourcePrepareFailure(inputs.kind, err)
		return failUpdateSkillItem(item, lock, status, code, message), nil
	}

	effectivePolicy, effectivePolicyLoaded, repoPolicyErr := resolveUpdateEvaluationPolicyWithDeps(inputs.kind, skillRoot, policyLoaded, cfg, deps)
	if repoPolicyErr != nil {
		return failUpdateSkillItem(item, lock, reportStatusError, updateCodeEvaluationError, repoPolicyErr.Error()), nil
	}

	findingsEvaluation, err := evaluateUpdateSourceFindings(skillRoot, inputs.policyProfile, effectivePolicyLoaded, effectivePolicy, lock.Policy.SeverityOverrides)
	if err != nil {
		return updateSkillItem{}, err
	}
	if findingsEvaluation.failure != nil {
		return failUpdateSkillItem(item, lock, findingsEvaluation.failure.status, findingsEvaluation.failure.code, findingsEvaluation.failure.message), nil
	}
	item.Findings = findingsEvaluation.findings
	item.Decision = findingsEvaluation.decision
	item.SeverityOverrides = findingsEvaluation.severityOverrides
	item.SeverityOverrideDiff = findingsEvaluation.severityOverrideDiff

	item, err = evaluateUpdateSourceChanges(item, lock, skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}

	return finalizeUpdateSkillStatus(item), nil
}

func evaluateUpdateSourceChanges(item updateSkillItem, lock installLock, skillRoot string) (updateSkillItem, error) {
	excludeMeta := map[string]struct{}{
		installReportFile: {},
		installLockFile:   {},
	}
	currentFiles, _, err := buildFileDigestsFiltered(skillRoot, excludeMeta)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.Diff = evaluateUpdateFileDiff(lock.Skill.Files, currentFiles, excludeMeta)

	signals, err := collectUpdateSignals(item.Path, skillRoot)
	if err != nil {
		return updateSkillItem{}, err
	}
	item.NewURLs = signals.newURLs
	item.NewExecutableFiles = signals.newExecutableFiles

	riskEvaluation := evaluateUpdateRisk(lock.Findings, item.Findings, item)
	item.Risk = riskEvaluation.risk
	item.RiskScore = riskEvaluation.score
	return item, nil
}

type updateSourceFindingsEvaluation struct {
	findings             []inspectFinding
	decision             string
	severityOverrides    []severityOverrideAudit
	severityOverrideDiff updateSeverityOverrideDiff
	failure              *updateSkillFailure
}

func evaluateUpdateSourceFindings(skillRoot string, policyProfile string, policyLoaded bool, cfg policypkg.Config, configuredOverrides []severityOverrideAudit) (updateSourceFindingsEvaluation, error) {
	rejectSeverities, err := policypkg.EffectiveRejectSeverities(policypkg.NormalizeProfile(policyProfile), policyLoaded, cfg)
	if err != nil {
		return updateSourceFindingsEvaluation{
			failure: &updateSkillFailure{reportStatusError, updateCodeEvaluationError, err.Error()},
		}, nil
	}
	rejectSet := rejectSeverities.Strings()

	findings, _, _, err := evaluateSkillWithOverrides(skillRoot, policyProfile, nil, rejectSet)
	if err != nil {
		return updateSourceFindingsEvaluation{}, err
	}
	evaluation := evaluateUpdateFindings(findings, configuredOverrides, rejectSet)
	return updateSourceFindingsEvaluation{
		findings:             findings,
		decision:             evaluation.decision,
		severityOverrides:    evaluation.severityOverrides,
		severityOverrideDiff: evaluation.severityOverrideDiff,
	}, nil
}

type updateSignalDiffs struct {
	newURLs            []string
	newExecutableFiles []string
}

func collectUpdateSignals(installedRoot string, currentRoot string) (updateSignalDiffs, error) {
	previousURLs, err := collectURLs(installedRoot)
	if err != nil {
		return updateSignalDiffs{}, err
	}
	currentURLs, err := collectURLs(currentRoot)
	if err != nil {
		return updateSignalDiffs{}, err
	}
	previousExec, err := collectExecutableFiles(installedRoot)
	if err != nil {
		return updateSignalDiffs{}, err
	}
	currentExec, err := collectExecutableFiles(currentRoot)
	if err != nil {
		return updateSignalDiffs{}, err
	}
	return updateSignalDiffs{
		newURLs:            setDiff(currentURLs, previousURLs),
		newExecutableFiles: setDiff(currentExec, previousExec),
	}, nil
}

func evaluateUpdateFileDiff(previousFiles []lockFileHash, currentFiles []lockFileHash, exclude map[string]struct{}) updateDiff {
	filteredPrevious := filterLockFiles(previousFiles, exclude)
	missing, changed, unexpected := diffLockFiles(filteredPrevious, currentFiles)
	return updateDiff{
		Added:   unexpected,
		Removed: missing,
		Changed: changed,
	}
}

type updateRiskEvaluation struct {
	risk  updateRisk
	score updateRiskScore
}

func evaluateUpdateRisk(previous lockFindingSummary, findings []inspectFinding, item updateSkillItem) updateRiskEvaluation {
	currentRisk := summarizeFindingSeverities(findings)
	signals := updateRiskSignalInputs{
		NewURLs:         len(item.NewURLs),
		NewExecutables:  len(item.NewExecutableFiles),
		FileDelta:       len(item.Diff.Added) + len(item.Diff.Removed) + len(item.Diff.Changed),
		OverrideAdded:   len(item.SeverityOverrideDiff.Added),
		OverrideRemoved: len(item.SeverityOverrideDiff.Removed),
	}
	return updateRiskEvaluation{
		risk: updateRisk{
			Previous: previous,
			Current:  currentRisk,
			Delta: lockFindingSummary{
				Critical: currentRisk.Critical - previous.Critical,
				High:     currentRisk.High - previous.High,
				Medium:   currentRisk.Medium - previous.Medium,
				Low:      currentRisk.Low - previous.Low,
			},
		},
		score: computeUpdateRiskScore(previous, currentRisk, signals),
	}
}

type updateFindingEvaluation struct {
	decision             string
	severityOverrides    []severityOverrideAudit
	severityOverrideDiff updateSeverityOverrideDiff
}

func evaluateUpdateFindings(findings []inspectFinding, configuredOverrides []severityOverrideAudit, rejectSet map[string]struct{}) updateFindingEvaluation {
	configuredByRule := make(map[string]severityOverrideAudit, len(configuredOverrides))
	for _, override := range configuredOverrides {
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
			decision = reportDecisionRejected
		}
	}

	previousOverrideIDs := policypkg.SortedAuditMapKeys(configuredByRule)
	currentOverrideIDs := policypkg.SortedAuditMapKeys(activeByRule)
	return updateFindingEvaluation{
		decision:          decision,
		severityOverrides: []severityOverrideAudit(policypkg.AuditValues(activeByRule).Sorted()),
		severityOverrideDiff: updateSeverityOverrideDiff{
			Added:   setDiff(currentOverrideIDs, previousOverrideIDs),
			Removed: setDiff(previousOverrideIDs, currentOverrideIDs),
		},
	}
}

func finalizeUpdateSkillStatus(item updateSkillItem) updateSkillItem {
	switch {
	case item.Decision == reportDecisionRejected:
		item.Status = reportDecisionRejected
		item.ErrorCode = updateCodePolicyRejected
		item.Message = "fresh policy evaluation rejected update source"
	case updateSkillHasChanges(item):
		item.Status = "CHANGED"
		item.ErrorCode = updateCodeChanged
		item.Message = "update source differs from installed lock snapshot"
	default:
		item.Status = "UP_TO_DATE"
		item.ErrorCode = updateCodeUpToDate
		item.Message = "no change detected against installed lock snapshot"
	}
	item.RuleID = rulepkg.InferIDForJSONError(item.Message)
	return item
}

func updateSkillHasChanges(item updateSkillItem) bool {
	return len(item.Diff.Added) > 0 ||
		len(item.Diff.Removed) > 0 ||
		len(item.Diff.Changed) > 0 ||
		item.Risk.Delta.Critical != 0 ||
		item.Risk.Delta.High != 0 ||
		item.Risk.Delta.Medium != 0 ||
		item.Risk.Delta.Low != 0 ||
		len(item.NewURLs) > 0 ||
		len(item.NewExecutableFiles) > 0 ||
		len(item.SeverityOverrideDiff.Added) > 0 ||
		len(item.SeverityOverrideDiff.Removed) > 0
}

type updateSkillFailure struct {
	status  string
	code    string
	message string
}

func classifyUpdateSourcePrepareFailure(kind string, err error) (status string, code string) {
	status = reportStatusError
	code = updateCodeSourcePrepareError
	if kind == "github-source" && isGitHubRefNotPinnedError(err) {
		return reportDecisionRejected, updateCodeGitHubRefFloating
	}
	return status, code
}

func failUpdateSkillItem(item updateSkillItem, lock installLock, status string, code string, message string) updateSkillItem {
	item.Status = status
	item.ErrorCode = code
	item.Message = message
	item.RuleID = rulepkg.InferIDForJSONError(item.Message)
	item.Risk = updateRisk{
		Previous: lock.Findings,
		Current:  lock.Findings,
	}
	return item
}
