package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func rejectSymlinkPath(path string, label string, ruleID string) error {
	for _, candidate := range symlinkCheckCandidates(path) {
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				return nil
			}
			return fmt.Errorf("failed to evaluate %s: %w", label, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: %s must not be a symlink: %s", ruleID, label, path)
		}
	}
	return nil
}

func symlinkCheckCandidates(path string) []string {
	cleanPath := filepath.Clean(path)
	candidates := []string{cleanPath}

	for current := cleanPath; ; {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		candidates = append(candidates, parent)
		current = parent
	}

	for i, j := 0, len(candidates)-1; i < j; i, j = i+1, j-1 {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}

	return candidates
}
