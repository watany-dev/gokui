package app

import (
	"fmt"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func canonicalGitHubSourceInput(spec srcpkg.GitHubSpec) string {
	return fmt.Sprintf("github:%s/%s//%s@%s", spec.Owner, spec.Repo, spec.Path, spec.Ref)
}
