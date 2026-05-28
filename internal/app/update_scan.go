package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
)

var updateURLPattern = regexp.MustCompile(`(?i)(?:https?://\[[0-9a-z:._%-]+\](?::\d+)?[^\s<>"')]*|https?://[^\s<>"')\]]+|//\[[0-9a-z:._%-]+\](?::\d+)?[^\s<>"')]*|//[^\s<>"')\]]+)`)

var (
	updateMaxURLScanFileBytes int64 = 1_000_000
	updateMaxScanFiles              = 10_000
)

func collectURLs(root string) ([]string, error) {
	if err := ensureUpdateScanRoot(root, "URL scan", rulepkg.UpdateURLScanSymlink.ID, rulepkg.UpdateURLScanSpecialFile.ID); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 32)
	scannedFiles := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !isMarkdownLikeFile(d.Name()) {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: URL scan input contains symlink: %s", rulepkg.UpdateURLScanSymlink.ID, path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file for URL scan: %w", err)
		}
		if err := ensureURLScanRegularFile(info, path, root); err != nil {
			return err
		}
		previousInfo := info
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to read file for URL scan: %w", err)
		}
		defer f.Close()
		info, err = f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file for URL scan: %w", err)
		}
		if err := ensureURLScanRegularFile(info, path, root); err != nil {
			return err
		}
		if err := ensureURLScanStableFile(previousInfo, info, path, root); err != nil {
			return err
		}
		scannedFiles++
		if scannedFiles > updateMaxScanFiles {
			return fmt.Errorf("URL scan exceeded max file count: %d", updateMaxScanFiles)
		}
		content, err := readURLScanContent(f, path, root)
		if err != nil {
			return err
		}
		matches := updateURLPattern.FindAllString(content, -1)
		for _, m := range matches {
			set[m] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func ensureURLScanRegularFile(info os.FileInfo, path string, root string) error {
	if info.Mode().IsRegular() {
		return nil
	}
	rel, relErr := filepath.Rel(root, path)
	if relErr == nil {
		path = filepath.ToSlash(rel)
	}
	return fmt.Errorf("%s: URL scan input contains non-regular file: %s", rulepkg.UpdateURLScanSpecialFile.ID, path)
}

func relativePathForMessage(path string, root string) string {
	rel, relErr := filepath.Rel(root, path)
	if relErr == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

func ensureURLScanStableFile(previous os.FileInfo, current os.FileInfo, path string, root string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     relativePathForMessage(path, root),
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: URL scan source changed during read: %s", rulepkg.UpdateURLScanSourceChangedDuringRead.ID, path)
		},
	}.CheckCurrent(current)
}

func collectExecutableFiles(root string) ([]string, error) {
	if err := ensureUpdateScanRoot(root, "executable scan", rulepkg.UpdateExecutableScanSymlink.ID, rulepkg.UpdateExecutableScanSpecialFile.ID); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 16)
	scannedFiles := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: executable scan input contains symlink: %s", rulepkg.UpdateExecutableScanSymlink.ID, path)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return fmt.Errorf("%s: executable scan input contains non-regular file: %s", rulepkg.UpdateExecutableScanSpecialFile.ID, path)
		}
		scannedFiles++
		if scannedFiles > updateMaxScanFiles {
			return fmt.Errorf("executable scan exceeded max file count: %d", updateMaxScanFiles)
		}
		if info.Mode().Perm()&0o111 == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		set[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mapKeysSorted(set), nil
}

func readURLScanContent(r io.Reader, path string, root string) (string, error) {
	var content bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&content, r, updateMaxURLScanFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			rel, relErr := filepath.Rel(root, path)
			if relErr == nil {
				path = filepath.ToSlash(rel)
			}
			return "", fmt.Errorf("markdown file exceeds URL scan size limit: %s", path)
		}
		return "", fmt.Errorf("failed to read file for URL scan: %w", err)
	}
	if !utf8.Valid(content.Bytes()) {
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil {
			path = filepath.ToSlash(rel)
		}
		return "", fmt.Errorf("%s: markdown file must be valid UTF-8: %s", rulepkg.UpdateURLScanInvalidUTF8.ID, path)
	}
	return content.String(), nil
}

func ensureUpdateScanRoot(root string, label string, symlinkRuleID string, specialRuleID string) error {
	return safefs.RootCheck{
		Root:            root,
		Label:           label,
		SymlinkRuleID:   symlinkRuleID,
		SpecialRuleID:   specialRuleID,
		StatErrorPrefix: fmt.Sprintf("failed to stat %s root", label),
	}.Validate()
}

func mapKeysSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setDiff(current []string, previous []string) []string {
	previousSet := make(map[string]struct{}, len(previous))
	for _, v := range previous {
		previousSet[v] = struct{}{}
	}
	out := make([]string, 0, len(current))
	for _, v := range current {
		if _, ok := previousSet[v]; !ok {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func isMarkdownLikeFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".md") ||
		strings.HasSuffix(lower, ".markdown") ||
		strings.HasSuffix(lower, ".txt")
}
