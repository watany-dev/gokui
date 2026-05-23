package app

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func rejectSymlinkPath(path string, label string, ruleID string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			return nil
		}
		return fmt.Errorf("failed to evaluate %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %s must not be a symlink: %s", ruleID, label, path)
	}
	return nil
}
