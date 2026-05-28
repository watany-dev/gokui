package app

import (
	"errors"
	"fmt"
	"io"

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

	return writeUpdateSuccessReport(parsed.Format, report, stdout)
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
