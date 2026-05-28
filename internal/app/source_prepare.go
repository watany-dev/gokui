package app

import (
	"errors"
	"fmt"
	"path/filepath"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

var fetchGitHubSkill = srcpkg.FetchGitHubSkill

var errGitHubRefNotPinned = errors.New("github source requires a commit-pinned ref")

type policyEvaluationSourceDeps struct {
	FetchGitHubSkill func(srcpkg.GitHubSpec) (string, func(), error)
}

func defaultPolicyEvaluationSourceDeps() policyEvaluationSourceDeps {
	return policyEvaluationSourceDeps{
		FetchGitHubSkill: fetchGitHubSkill,
	}
}

func preparePolicyEvaluationSource(input string, sourceKind string) (skillRoot string, cleanup func(), err error) {
	return preparePolicyEvaluationSourceWithDeps(input, sourceKind, defaultPolicyEvaluationSourceDeps())
}

func preparePolicyEvaluationSourceWithDeps(input string, sourceKind string, deps policyEvaluationSourceDeps) (skillRoot string, cleanup func(), err error) {
	switch sourceKind {
	case "github-source":
		spec, parseErr := srcpkg.ParseGitHubSource(input)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid github source: %w", parseErr)
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return "", nil, fmt.Errorf("%w (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)", errGitHubRefNotPinned)
		}

		fetch := deps.FetchGitHubSkill
		if fetch == nil {
			fetch = srcpkg.FetchGitHubSkill
		}
		root, release, fetchErr := fetch(spec)
		if fetchErr != nil {
			if release != nil {
				release()
			}
			return "", nil, fetchErr
		}
		if validateErr := validateLocalDirInspectSource(root); validateErr != nil {
			if release != nil {
				release()
			}
			return "", nil, validateErr
		}
		return root, release, nil
	default:
		root, release, prepErr := prepareInspectSource(input, sourceKind)
		if prepErr != nil {
			return "", nil, prepErr
		}
		return filepath.Clean(root), release, nil
	}
}

func isGitHubRefNotPinnedError(err error) bool {
	return errors.Is(err, errGitHubRefNotPinned)
}
