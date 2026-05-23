package app

import (
	"fmt"
	"path/filepath"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

var fetchGitHubSkill = srcpkg.FetchGitHubSkill

func preparePolicyEvaluationSource(input string, sourceKind string) (skillRoot string, cleanup func(), err error) {
	switch sourceKind {
	case "github-source":
		spec, parseErr := srcpkg.ParseGitHubSource(input)
		if parseErr != nil {
			return "", nil, fmt.Errorf("invalid github source: %w", parseErr)
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return "", nil, fmt.Errorf("github source requires a commit-pinned ref (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)")
		}

		root, release, fetchErr := fetchGitHubSkill(spec)
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
