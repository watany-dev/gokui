package app

import policypkg "github.com/watany-dev/gokui/internal/policy"

func buildUpdateReport(targetRoot string, policyLoaded bool, cfg policypkg.Config) (updateReport, error) {
	return buildUpdateReportWithDeps(targetRoot, policyLoaded, cfg, defaultUpdateDeps())
}

func evaluateUpdateSkill(item updateSkillItem, lock installLock, policyLoaded bool, cfg policypkg.Config) (updateSkillItem, error) {
	return evaluateUpdateSkillWithDeps(item, lock, policyLoaded, cfg, defaultUpdateDeps())
}

func resolveUpdateEvaluationPolicy(kind string, skillRoot string, policyLoaded bool, cfg policypkg.Config) (policypkg.Config, bool, error) {
	return resolveUpdateEvaluationPolicyWithDeps(kind, skillRoot, policyLoaded, cfg, defaultUpdateDeps())
}
