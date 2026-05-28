package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/watany-dev/gokui/internal/rule"
)

func scanTargets(skillRoot string) ([]scanTarget, error) {
	rootInfo, rootErr := os.Lstat(skillRoot)
	if rootErr != nil {
		return nil, fmt.Errorf("failed walking skill files for scan: %w", rootErr)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("failed walking skill files for scan: %s: scan source root must not be a symlink: %s", rule.SymlinkInScanSource.ID, skillRoot)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("failed walking skill files for scan: %s: scan source root must be a directory: %s", rule.SpecialFileInScanSource.ID, skillRoot)
	}

	entries := make([]scanTarget, 0, 16)
	scannedFiles := 0
	err := filepath.WalkDir(skillRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(skillRoot, path)
		if err != nil {
			return fmt.Errorf("failed to compute relative path for scan: %w", err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: scan source contains symlink: %s", rule.SymlinkInScanSource.ID, rel)
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return fmt.Errorf("failed to stat scan source file: %w", infoErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: scan source contains non-regular file: %s", rule.SpecialFileInScanSource.ID, rel)
		}
		scannedFiles++
		if scannedFiles > scanMaxFiles {
			return fmt.Errorf("%s: scan source exceeded max file count: %d", rule.ScanFileCountExceeded.ID, scanMaxFiles)
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".md") {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "markdown",
				Info:     info,
			})
			return nil
		}
		ext := strings.ToLower(filepath.Ext(lower))
		if _, ok := scriptLikeExtensions[ext]; ok {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "script",
				Info:     info,
			})
			return nil
		}
		if _, ok := manifestLikeFiles[lower]; ok {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "manifest",
				Info:     info,
			})
			return nil
		}
		isShebangScript, probeErr := hasScriptShebang(path)
		if probeErr != nil {
			return fmt.Errorf("failed to inspect scan source file type: %w", probeErr)
		}
		if info.Mode()&0o111 != 0 || isShebangScript {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "script",
				Info:     info,
			})
			return nil
		}
		entries = append(entries, scanTarget{
			Absolute: path,
			Relative: rel,
			Kind:     "unknown",
			Info:     info,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed walking skill files for scan: %w", err)
	}
	return entries, nil
}

func hasScriptShebang(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, maxShebangProbeBytes)
	n, readErr := f.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, readErr
	}
	if n == 0 {
		return false, nil
	}

	content := string(buf[:n])
	content = strings.TrimPrefix(content, "\ufeff")
	content = strings.TrimLeft(content, " \t")
	return strings.HasPrefix(content, "#!"), nil
}
