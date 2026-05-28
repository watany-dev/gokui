package app

import policypkg "github.com/watany-dev/gokui/internal/policy"

func normalizeInspectDeps(deps inspectDeps) inspectDeps {
	if deps.PrepareEvaluationSource == nil {
		deps.PrepareEvaluationSource = preparePolicyEvaluationSource
	}
	if deps.PrepareInspectSource == nil {
		deps.PrepareInspectSource = prepareInspectSource
	}
	return deps
}

func normalizeVetDeps(deps vetDeps) vetDeps {
	if deps.LoadUserPolicy == nil {
		deps.LoadUserPolicy = policypkg.LoadUserPolicy
	}
	if deps.LoadRepositoryPolicy == nil {
		deps.LoadRepositoryPolicy = policypkg.LoadRepositoryPolicy
	}
	if deps.RunInspect == nil {
		deps.RunInspect = runInspect
	}
	return deps
}
