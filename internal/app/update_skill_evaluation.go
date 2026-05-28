package app

import (
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

type updateSkillEvaluationContext struct {
	item                  updateSkillItem
	lock                  installLock
	policyLoaded          bool
	policyConfig          policypkg.Config
	deps                  updateDeps
	inputs                updateEvaluationInputs
	skillRoot             string
	cleanup               func()
	effectivePolicy       policypkg.Config
	effectivePolicyLoaded bool
}

type updateSkillEvaluationStep func(*updateSkillEvaluationContext) (*updateSkillFailure, error)

var updateSkillEvaluationSteps = []updateSkillEvaluationStep{
	validateUpdateSkillEvaluationLock,
	prepareUpdateSkillEvaluationSource,
	resolveUpdateSkillEvaluationPolicy,
	evaluateUpdateSkillEvaluationFindings,
	evaluateUpdateSkillEvaluationChanges,
}

func (ctx *updateSkillEvaluationContext) evaluate() (updateSkillItem, error) {
	ctx.item.RiskScore = computeUpdateRiskScore(ctx.lock.Findings, ctx.lock.Findings, updateRiskSignalInputs{})
	for _, step := range updateSkillEvaluationSteps {
		failure, err := step(ctx)
		if ctx.cleanup != nil {
			defer ctx.cleanup()
			ctx.cleanup = nil
		}
		if err != nil {
			return updateSkillItem{}, err
		}
		if failure == nil {
			continue
		}
		return failUpdateSkillItem(ctx.item, ctx.lock, failure.status, failure.code, failure.message), nil
	}
	return finalizeUpdateSkillStatus(ctx.item), nil
}

func validateUpdateSkillEvaluationLock(ctx *updateSkillEvaluationContext) (*updateSkillFailure, error) {
	inputs, failure := validateUpdateLockForEvaluation(ctx.item, ctx.lock)
	if failure != nil {
		return failure, nil
	}
	ctx.inputs = inputs
	return nil, nil
}

func prepareUpdateSkillEvaluationSource(ctx *updateSkillEvaluationContext) (*updateSkillFailure, error) {
	skillRoot, cleanup, err := ctx.deps.PrepareEvaluationSource(ctx.inputs.sourceInput, ctx.inputs.kind)
	ctx.cleanup = cleanup
	if err != nil {
		message := err.Error()
		status, code := classifyUpdateSourcePrepareFailure(ctx.inputs.kind, err)
		return &updateSkillFailure{status: status, code: code, message: message}, nil
	}
	ctx.skillRoot = skillRoot
	return nil, nil
}

func resolveUpdateSkillEvaluationPolicy(ctx *updateSkillEvaluationContext) (*updateSkillFailure, error) {
	effectivePolicy, effectivePolicyLoaded, err := resolveUpdateEvaluationPolicyWithDeps(ctx.inputs.kind, ctx.skillRoot, ctx.policyLoaded, ctx.policyConfig, ctx.deps)
	if err != nil {
		return &updateSkillFailure{status: reportStatusError, code: updateCodeEvaluationError, message: err.Error()}, nil
	}
	ctx.effectivePolicy = effectivePolicy
	ctx.effectivePolicyLoaded = effectivePolicyLoaded
	return nil, nil
}

func evaluateUpdateSkillEvaluationFindings(ctx *updateSkillEvaluationContext) (*updateSkillFailure, error) {
	evaluation, err := evaluateUpdateSourceFindings(ctx.skillRoot, ctx.inputs.policyProfile, ctx.effectivePolicyLoaded, ctx.effectivePolicy, ctx.lock.Policy.SeverityOverrides)
	if err != nil {
		return nil, err
	}
	if evaluation.failure != nil {
		return evaluation.failure, nil
	}
	ctx.item.Findings = evaluation.findings
	ctx.item.Decision = evaluation.decision
	ctx.item.SeverityOverrides = evaluation.severityOverrides
	ctx.item.SeverityOverrideDiff = evaluation.severityOverrideDiff
	return nil, nil
}

func evaluateUpdateSkillEvaluationChanges(ctx *updateSkillEvaluationContext) (*updateSkillFailure, error) {
	item, err := evaluateUpdateSourceChanges(ctx.item, ctx.lock, ctx.skillRoot)
	if err != nil {
		return nil, err
	}
	ctx.item = item
	return nil, nil
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
	severityOverrides    []policypkg.SeverityOverrideAudit
	severityOverrideDiff updateSeverityOverrideDiff
	failure              *updateSkillFailure
}

func evaluateUpdateSourceFindings(skillRoot string, policyProfile string, policyLoaded bool, cfg policypkg.Config, configuredOverrides []policypkg.SeverityOverrideAudit) (updateSourceFindingsEvaluation, error) {
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
	severityOverrides    []policypkg.SeverityOverrideAudit
	severityOverrideDiff updateSeverityOverrideDiff
}

func evaluateUpdateFindings(findings []inspectFinding, configuredOverrides []policypkg.SeverityOverrideAudit, rejectSet map[string]struct{}) updateFindingEvaluation {
	configuredByRule := make(map[string]policypkg.SeverityOverrideAudit, len(configuredOverrides))
	for _, override := range configuredOverrides {
		if _, exists := configuredByRule[override.RuleID]; exists {
			continue
		}
		configuredByRule[override.RuleID] = override
	}

	activeByRule := make(map[string]policypkg.SeverityOverrideAudit, len(configuredByRule))
	decision := "PASS"
	for _, finding := range findings {
		effectiveSeverity := finding.Severity
		if override, ok := configuredByRule[finding.ID]; ok {
			if effectiveSeverity == policypkg.SeverityHigh {
				effectiveSeverity = policypkg.SeverityMedium
			}
			activeByRule[finding.ID] = override
		}
		if _, shouldReject := rejectSet[strings.ToLower(strings.TrimSpace(effectiveSeverity.String()))]; shouldReject {
			decision = reportDecisionRejected
		}
	}

	previousOverrideIDs := policypkg.SortedAuditMapKeys(configuredByRule)
	currentOverrideIDs := policypkg.SortedAuditMapKeys(activeByRule)
	return updateFindingEvaluation{
		decision:          decision,
		severityOverrides: []policypkg.SeverityOverrideAudit(policypkg.AuditValues(activeByRule).Sorted()),
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
