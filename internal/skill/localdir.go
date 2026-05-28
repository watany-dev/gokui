package skill

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const RuleInspectSourceSymlink = "INSPECT_SOURCE_SYMLINK_DETECTED"

var ErrInspectSourceNotFound = errors.New("inspect source not found")

func ValidateLocalDirInspectSource(input string, maxFrontmatterBytes int64) error {
	if err := rejectSymlinkPath(input, "inspect local source", RuleInspectSourceSymlink); err != nil {
		return err
	}
	info, lstatErr := os.Lstat(input)
	if lstatErr != nil {
		return fmt.Errorf("%w: %s", ErrInspectSourceNotFound, input)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: inspect local source must not be a symlink: %s", RuleInspectSourceSymlink, input)
	}
	if !info.IsDir() {
		return fmt.Errorf("inspect local source must be a directory: %s", input)
	}

	skillPath := filepath.Join(input, "SKILL.md")
	if err := rejectSymlinkPath(skillPath, "inspect local source SKILL.md", RuleFrontmatterSymlink); err != nil {
		return err
	}
	skillInfo, skillErr := os.Lstat(skillPath)
	if skillErr != nil {
		return fmt.Errorf("inspect local dir must contain SKILL.md at root: %s", input)
	}
	if skillInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: inspect local source SKILL.md must not be a symlink: %s", RuleFrontmatterSymlink, skillPath)
	}

	meta, err := ValidateFrontmatter(skillPath, maxFrontmatterBytes)
	if err != nil {
		return err
	}

	dirName := filepath.Base(filepath.Clean(input))
	if dirName != meta.Name {
		return fmt.Errorf("frontmatter name must match directory name: name=%s dir=%s", meta.Name, dirName)
	}

	return nil
}

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
			if isRootLevelPathComponent(candidate) {
				continue
			}
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

func isRootLevelPathComponent(path string) bool {
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) {
		return false
	}
	parent := filepath.Dir(cleanPath)
	if parent == cleanPath {
		return false
	}
	return filepath.Dir(parent) == parent
}
