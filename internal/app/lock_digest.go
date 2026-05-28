package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/watany-dev/gokui/internal/limitio"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
)

func buildFileDigestsForLock(root string) ([]lockFileHash, string, error) {
	exclude := map[string]struct{}{
		installLockFile: {},
	}
	return buildFileDigestsFiltered(root, exclude)
}

func buildFileDigestsFiltered(root string, exclude map[string]struct{}) ([]lockFileHash, string, error) {
	if err := ensureInstallTreeRoot(root, "digest input", rulepkg.InstallDigestSymlink.ID, rulepkg.InstallDigestSpecialFile.ID); err != nil {
		return nil, "", fmt.Errorf("%w: %w", errDigestBuildFailed, err)
	}
	files := make([]lockFileHash, 0, 32)
	digestedFiles := 0
	var totalBytes int64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("failed to compute digest path: %w", err)
		}
		rel = filepath.ToSlash(rel)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat file for digest: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: digest input contains symlink: %s", rulepkg.InstallDigestSymlink.ID, rel)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: digest input contains non-regular file: %s", rulepkg.InstallDigestSpecialFile.ID, rel)
		}
		if _, skip := exclude[rel]; skip {
			return nil
		}
		if info.Size() > installMaxDigestFileBytes {
			return fmt.Errorf("%s: digest input file exceeds size limit: %s", rulepkg.InstallDigestFileTooLarge.ID, rel)
		}
		digestedFiles++
		if digestedFiles > installMaxDigestFiles {
			return fmt.Errorf("%s: digest input exceeds max file count: %d", rulepkg.InstallDigestFileCountExceeded.ID, installMaxDigestFiles)
		}
		totalBytes += info.Size()
		if totalBytes > installMaxDigestTotalBytes {
			return fmt.Errorf("%s: digest input exceeds max total bytes: %d", rulepkg.InstallDigestTotalBytesExceeded.ID, installMaxDigestTotalBytes)
		}
		sum, size, err := limitio.HashSHA256FileWithLimitChecked(path, installMaxDigestFileBytes, info, ensureInstallDigestStableFromOpen)
		if err != nil {
			if errors.Is(err, limitio.ErrSizeExceeded) {
				return fmt.Errorf("%s: digest input file exceeds size limit: %s", rulepkg.InstallDigestFileTooLarge.ID, rel)
			}
			return err
		}
		files = append(files, lockFileHash{
			Path:   rel,
			SHA256: sum,
			Bytes:  size,
		})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errDigestBuildFailed, err)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	rootHasher := sha256.New()
	for _, file := range files {
		_, _ = io.WriteString(rootHasher, file.Path)
		_, _ = io.WriteString(rootHasher, "\x00")
		_, _ = io.WriteString(rootHasher, file.SHA256)
		_, _ = io.WriteString(rootHasher, "\x00")
	}
	return files, hex.EncodeToString(rootHasher.Sum(nil)), nil
}

func ensureInstallTreeRoot(root string, label string, symlinkRuleID string, specialRuleID string) error {
	return safefs.RootCheck{
		Root:          root,
		Label:         label,
		SymlinkRuleID: symlinkRuleID,
		SpecialRuleID: specialRuleID,
	}.Validate()
}

func ensureInstallDigestStableFromOpen(previous os.FileInfo, opened fileInfoStatter, path string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     path,
		StatError: func(path string) error {
			return fmt.Errorf("failed to open file for hashing: %s", path)
		},
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: digest input file changed during hash: %s", rulepkg.InstallDigestSourceChangedDuringHash.ID, path)
		},
	}.CheckOpened(opened)
}
