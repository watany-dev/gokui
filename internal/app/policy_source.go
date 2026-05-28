package app

import "strings"

func shouldApplyRepositoryPolicy(sourceKind string) bool {
	return strings.EqualFold(strings.TrimSpace(sourceKind), "local-dir")
}
