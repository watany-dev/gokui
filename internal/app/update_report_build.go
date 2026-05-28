package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func normalizeUpdateDeps(deps updateDeps) updateDeps {
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

func buildUpdateReportWithDeps(targetRoot string, policyLoaded bool, cfg policypkg.Config, deps updateDeps) (updateReport, error) {
	deps = normalizeUpdateDeps(deps)
	cleanTarget := filepath.Clean(targetRoot)
	entries, err := os.ReadDir(cleanTarget)
	if err != nil {
		return updateReport{}, fmt.Errorf("%w: %s", errUpdateTargetRead, cleanTarget)
	}

	skills := make([]updateSkillItem, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return updateReport{}, fmt.Errorf("%s: update target entry must not be a symlink: %s", rulepkg.UpdateTargetEntrySymlink.ID, filepath.Join(cleanTarget, entry.Name()))
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
			SeverityOverrides:  []policypkg.SeverityOverrideAudit{},
			SeverityOverrideDiff: updateSeverityOverrideDiff{
				Added:   []string{},
				Removed: []string{},
			},
		}
		lockPath := filepath.Join(skillPath, installLockFile)
		lock, err := readInstallLock(lockPath)
		if err != nil {
			item.Status = reportStatusError
			item.ErrorCode = updateCodeLockfileInvalid
			item.Message = "missing or invalid lockfile"
			item.RuleID = rulepkg.InferIDForJSONError(item.Message)
			skills = append(skills, item)
			continue
		}
		item.Source = source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		}
		item.SeverityOverrides = []policypkg.SeverityOverrideAudit(policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides).Clone())

		enriched, err := evaluateUpdateSkillWithDeps(item, lock, policyLoaded, cfg, deps)
		if err != nil {
			item.Status = reportStatusError
			item.ErrorCode = updateCodeEvaluationError
			item.Message = err.Error()
			item.RuleID = rulepkg.InferIDForJSONError(item.Message)
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
