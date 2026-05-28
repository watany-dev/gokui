package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

func validateUpdateLockPolicy(policy lockPolicy) (string, error) {
	policyProfileRaw := policy.Profile
	if strings.IndexFunc(policyProfileRaw, isC0OrC1ControlRune) >= 0 {
		return "", fmt.Errorf("lock policy profile must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(policyProfileRaw) {
		return "", fmt.Errorf("lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	policyProfile := policypkg.NormalizeProfile(policyProfileRaw)
	if policyProfileRaw != policyProfile.String() {
		return "", fmt.Errorf("lock policy profile must be canonical lowercase without surrounding whitespace")
	}
	if _, err := policypkg.ParseProfile(policyProfile.String()); err != nil {
		return "", fmt.Errorf("unsupported policy profile in lockfile: %s", policyProfileRaw)
	}

	policyDecisionRaw := policy.Decision
	trimmedPolicyDecision := strings.TrimSpace(policyDecisionRaw)
	if strings.IndexFunc(policyDecisionRaw, isC0OrC1ControlRune) >= 0 {
		return "", fmt.Errorf("lock policy decision must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(policyDecisionRaw) {
		return "", fmt.Errorf("lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedPolicyDecision != policyDecisionRaw {
		return "", fmt.Errorf("lock policy decision must not contain leading or trailing whitespace")
	}
	if policyDecisionRaw != "pass" {
		return "", fmt.Errorf("lock policy decision must be canonical lowercase pass")
	}
	return policyProfile.String(), nil
}

func validateUpdateLockSource(lockSource lockSource) (string, string, *updateSkillFailure) {
	sourceInputRaw := lockSource.Input
	sourceInput := strings.TrimSpace(sourceInputRaw)
	if strings.IndexFunc(sourceInputRaw, isC0OrC1ControlRune) >= 0 {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source input must not contain C0/C1 control characters"}
	}
	if containsSeverityOverrideDisallowedUnicode(sourceInputRaw) && detectSourceKind(sourceInput) != "github-source" {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters"}
	}
	if sourceInput == "" {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source input is empty"}
	}
	if sourceInputRaw != sourceInput {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source input must not contain leading or trailing whitespace"}
	}

	kindRaw := lockSource.Kind
	kind := strings.TrimSpace(kindRaw)
	detectedKind := detectSourceKind(sourceInput)
	if strings.IndexFunc(kindRaw, isC0OrC1ControlRune) >= 0 {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source kind must not contain C0/C1 control characters"}
	}
	if containsSeverityOverrideDisallowedUnicode(kindRaw) {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters"}
	}
	if kind == "" {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source kind is empty"}
	}
	if kindRaw != kind {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source kind must not contain leading or trailing whitespace"}
	}
	if kind != strings.ToLower(kind) {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source kind must be canonical lowercase"}
	}
	expectedType := sourceTypeFromKind(kind)
	if expectedType == "unknown" {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, fmt.Sprintf("unsupported source kind in lockfile: %s", kind)}
	}
	if expectedType != "github" {
		cleanedInput := filepath.Clean(sourceInput)
		if sourceInput != cleanedInput {
			return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source input must be a canonical cleaned path for local/archive sources"}
		}
	}
	if kind != detectedKind {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeSourceMetadataBad, fmt.Sprintf("lock source kind does not match source input: kind=%s detected=%s", kind, detectedKind)}
	}

	sourceTypeRaw := lockSource.Type
	sourceType := strings.TrimSpace(sourceTypeRaw)
	if strings.IndexFunc(sourceTypeRaw, isC0OrC1ControlRune) >= 0 {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source type must not contain C0/C1 control characters"}
	}
	if containsSeverityOverrideDisallowedUnicode(sourceTypeRaw) {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters"}
	}
	if sourceType == "" {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source type is empty"}
	}
	if sourceTypeRaw != sourceType {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source type must not contain leading or trailing whitespace"}
	}
	if sourceType != strings.ToLower(sourceType) {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, "lock source type must be canonical lowercase"}
	}
	if sourceType != expectedType {
		return "", "", &updateSkillFailure{reportStatusError, updateCodeLockfileInvalid, fmt.Sprintf("source type mismatch for kind %s: expected %s, got %s", kind, expectedType, sourceType)}
	}
	return sourceInput, kind, nil
}

func validateUpdateLockEnvelope(lock installLock, expectedSkillName string) error {
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
		return fmt.Errorf("unsupported lock schema: %s", lock.Schema)
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
		return fmt.Errorf("lock name does not match installed skill directory: lock=%s dir=%s", lock.Name, expectedSkillName)
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
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return fmt.Errorf("lock findings summary is invalid: %v", err)
	}
	if err := policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides).Validate(); err != nil {
		return fmt.Errorf("lock policy severity_overrides is invalid: %v", err)
	}
	return nil
}

func validateUpdateLockAgainstInstallReport(skillPath string, lock installLock) error {
	skillInfo, skillStatErr := os.Lstat(skillPath)
	if skillStatErr != nil {
		return fmt.Errorf("failed to evaluate install report for update baseline: %w", skillStatErr)
	}
	if !skillInfo.IsDir() {
		return fmt.Errorf("failed to evaluate install report for update baseline: %s is not a directory", skillPath)
	}

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
