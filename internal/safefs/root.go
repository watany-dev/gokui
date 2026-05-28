package safefs

import (
	"fmt"
	"os"
)

// RootCheck validates a root path before traversing it.
type RootCheck struct {
	Root            string
	Label           string
	SymlinkRuleID   string
	SpecialRuleID   string
	StatErrorPrefix string
}

func (r RootCheck) Validate() error {
	rootInfo, err := os.Lstat(r.Root)
	if err != nil {
		if r.StatErrorPrefix != "" {
			return fmt.Errorf("%s: %w", r.StatErrorPrefix, err)
		}
		return err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: %s root must not be a symlink: %s", r.SymlinkRuleID, r.Label, r.Root)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("%s: %s root must be a directory: %s", r.SpecialRuleID, r.Label, r.Root)
	}
	return nil
}
