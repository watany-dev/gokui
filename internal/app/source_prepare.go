package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/watany-dev/gokui/internal/materialize"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

var errGitHubRefNotPinned = errors.New("github source requires a commit-pinned ref")

type policyEvaluationSourceDeps struct {
	FetchGitHubSkill func(srcpkg.GitHubSpec) (string, func(), error)
}

func defaultPolicyEvaluationSourceDeps() policyEvaluationSourceDeps {
	return policyEvaluationSourceDeps{
		FetchGitHubSkill: srcpkg.FetchGitHubSkill,
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

func prepareInspectSource(input string, sourceKind string) (skillRoot string, cleanup func(), err error) {
	switch sourceKind {
	case "local-dir":
		if validateErr := validateLocalDirInspectSource(input); validateErr != nil {
			return "", nil, validateErr
		}
		return input, nil, nil
	case "zip", "tar":
		return prepareArchiveInspectSource(input, sourceKind)
	default:
		return "", nil, fmt.Errorf("unsupported inspect source kind: %s", sourceKind)
	}
}

func prepareArchiveInspectSource(input string, sourceKind string) (string, func(), error) {
	tempRoot, err := os.MkdirTemp("", "gokui-inspect-archive-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create inspect quarantine: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tempRoot)
	}

	extractDir := filepath.Join(tempRoot, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to prepare inspect extraction directory: %w", err)
	}

	limits := materialize.Limits{
		MaxFiles:      1000,
		MaxTotalBytes: 50 * 1024 * 1024,
		MaxFileBytes:  10 * 1024 * 1024,
	}
	if err := materialize.ExtractArchive(input, sourceKind, extractDir, limits); err != nil {
		cleanup()
		return "", nil, err
	}

	skillRoot, err := materialize.DetectSkillRoot(extractDir)
	if err != nil {
		cleanup()
		return "", nil, err
	}

	if err := validateLocalDirInspectSource(skillRoot); err != nil {
		cleanup()
		return "", nil, err
	}

	return skillRoot, cleanup, nil
}

func isGitHubRefNotPinnedError(err error) bool {
	return errors.Is(err, errGitHubRefNotPinned)
}
