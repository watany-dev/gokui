package app

import (
	"fmt"

	policypkg "github.com/watany-dev/gokui/internal/policy"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type updateEvaluationInputs struct {
	policyProfile string
	sourceInput   string
	kind          string
}

type updateLockEvaluationContext struct {
	item   updateSkillItem
	lock   installLock
	inputs updateEvaluationInputs
}

type updateLockEvaluationCheck func(*updateLockEvaluationContext) *updateSkillFailure

var updateLockEvaluationChecks = []updateLockEvaluationCheck{
	checkUpdateLockEnvelope,
	checkUpdateLockPolicy,
	checkUpdateLockSource,
	checkUpdateLockGitHubSource,
	checkUpdateLockSkillSnapshot,
	checkUpdateLockInstallReport,
}

func validateUpdateLockForEvaluation(item updateSkillItem, lock installLock) (updateEvaluationInputs, *updateSkillFailure) {
	ctx := updateLockEvaluationContext{
		item: item,
		lock: lock,
	}
	for _, check := range updateLockEvaluationChecks {
		if failure := check(&ctx); failure != nil {
			return updateEvaluationInputs{}, failure
		}
	}
	return ctx.inputs, nil
}

func checkUpdateLockEnvelope(ctx *updateLockEvaluationContext) *updateSkillFailure {
	if err := validateUpdateLockEnvelope(ctx.lock, ctx.item.Name); err != nil {
		return &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, err.Error()}
	}
	return nil
}

func checkUpdateLockPolicy(ctx *updateLockEvaluationContext) *updateSkillFailure {
	policyProfile, err := validateUpdateLockPolicy(ctx.lock.Policy)
	if err != nil {
		return &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, err.Error()}
	}
	ctx.inputs.policyProfile = policyProfile
	return nil
}

func checkUpdateLockSource(ctx *updateLockEvaluationContext) *updateSkillFailure {
	sourceInput, kind, failure := validateUpdateLockSource(ctx.lock.Source)
	if failure != nil {
		return failure
	}
	ctx.inputs.sourceInput = sourceInput
	ctx.inputs.kind = kind
	return nil
}

func checkUpdateLockGitHubSource(ctx *updateLockEvaluationContext) *updateSkillFailure {
	return validateUpdateGitHubSource(ctx.item.Path, ctx.inputs.sourceInput, ctx.inputs.kind)
}

func checkUpdateLockSkillSnapshot(ctx *updateLockEvaluationContext) *updateSkillFailure {
	if err := validateUpdateLockSkillSnapshot(ctx.lock); err != nil {
		return &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, err.Error()}
	}
	return nil
}

func checkUpdateLockInstallReport(ctx *updateLockEvaluationContext) *updateSkillFailure {
	if err := validateUpdateLockAgainstInstallReport(ctx.item.Path, ctx.lock); err != nil {
		return &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, err.Error()}
	}
	return nil
}

func resolveUpdateEvaluationPolicyWithDeps(kind string, skillRoot string, policyLoaded bool, cfg policypkg.Config, deps updateDeps) (policypkg.Config, bool, error) {
	deps = normalizeUpdateDeps(deps)
	if !shouldApplyRepositoryPolicy(kind) {
		return cfg, policyLoaded, nil
	}
	repoPolicy, repoPolicyFound, repoPolicyErr := deps.LoadRepositoryPolicy(skillRoot)
	if repoPolicyErr != nil {
		return policypkg.Config{}, false, repoPolicyErr
	}
	if repoPolicyFound {
		return repoPolicy, true, nil
	}
	return cfg, policyLoaded, nil
}

func validateUpdateGitHubSource(installedPath string, sourceInput string, kind string) *updateSkillFailure {
	if kind != "github-source" {
		return nil
	}
	spec, parseErr := srcpkg.ParseGitHubSource(sourceInput)
	if parseErr != nil {
		return &updateSkillFailure{reportStatusError, updateCodeGitHubSourceBad, fmt.Sprintf("invalid github source in lockfile: %v", parseErr)}
	}
	if sourceInput != canonicalGitHubSourceInput(spec) {
		return &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "github lock source input must be canonical"}
	}
	if !srcpkg.IsCommitPinnedRef(spec.Ref) {
		return &updateSkillFailure{reportDecisionRejected, updateCodeGitHubRefFloating, "floating github refs are not eligible for update; commit-pinned ref required"}
	}
	if err := verifyInstalledSourceMetadata(installedPath, source{
		Input: sourceInput,
		Kind:  kind,
	}); err != nil {
		return &updateSkillFailure{reportStatusError, updateCodeSourceMetadataBad, err.Error()}
	}
	return nil
}
