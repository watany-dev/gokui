package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type installResult string

const (
	installResultInstalled        installResult = "installed"
	installResultAlreadyInstalled installResult = "already-installed"
)

func installSkillAtomic(skillRoot string, targetRoot string, skillName string, report installReport) (string, installResult, error) {
	finalPath := filepath.Join(targetRoot, skillName)
	if err := rejectSymlinkPath(finalPath, "install target entry", rulepkg.InstallTargetEntrySymlink.ID); err != nil {
		return "", "", err
	}

	stagingRoot, err := os.MkdirTemp(targetRoot, ".gokui-install-*")
	if err != nil {
		return "", "", fmt.Errorf("failed to create install staging directory: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagedSkill := filepath.Join(stagingRoot, skillName)
	if err := copyTreeNormalized(skillRoot, stagedSkill); err != nil {
		return "", "", err
	}

	report.InstalledPath = finalPath
	report.Installed = true
	if err := writeInstallMetadata(stagedSkill, report); err != nil {
		return "", "", err
	}

	stagedLock, err := readInstallLock(filepath.Join(stagedSkill, installLockFile))
	if err != nil {
		return "", "", err
	}

	finalInfo, err := os.Stat(finalPath)
	if err == nil {
		if !finalInfo.IsDir() {
			return "", "", fmt.Errorf("install target already contains non-directory path: %s", finalPath)
		}

		existingLock, readErr := readInstallLock(filepath.Join(finalPath, installLockFile))
		if readErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s", finalPath)
		}
		if validateErr := validateInstallLockForProvenanceReuse(existingLock, skillName); validateErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s (%v)", finalPath, validateErr)
		}
		if !provenanceMatches(existingLock, stagedLock) {
			return "", "", fmt.Errorf("install target already contains skill from different provenance: %s", finalPath)
		}
		if integrityErr := validateInstalledContentForIdempotentReuse(finalPath, existingLock); integrityErr != nil {
			return "", "", fmt.Errorf("install target already contains skill with missing/invalid lockfile: %s (%v)", finalPath, integrityErr)
		}
		return finalPath, installResultAlreadyInstalled, nil
	}
	if !os.IsNotExist(err) {
		return "", "", fmt.Errorf("failed to check install target: %w", err)
	}

	if err := os.Rename(stagedSkill, finalPath); err != nil {
		return "", "", fmt.Errorf("failed to finalize install: %w", err)
	}

	return finalPath, installResultInstalled, nil
}

func copyTreeNormalized(srcRoot string, dstRoot string) error {
	if err := ensureInstallTreeRoot(srcRoot, "install source", rulepkg.InstallSourceSymlink.ID, rulepkg.InstallSourceSpecialFile.ID); err != nil {
		return err
	}
	files := 0
	var totalBytes int64
	return filepath.WalkDir(srcRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return fmt.Errorf("failed to compute install path: %w", err)
		}
		if rel == "." {
			return os.MkdirAll(dstRoot, 0o755)
		}

		srcInfo, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to stat source file during install: %w", err)
		}
		if srcInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: install source contains symlink: %s", rulepkg.InstallSourceSymlink.ID, rel)
		}
		destPath := filepath.Join(dstRoot, rel)
		if d.IsDir() {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				return fmt.Errorf("failed to create install directory: %w", err)
			}
			return nil
		}
		if !srcInfo.Mode().IsRegular() {
			return fmt.Errorf("%s: install source contains non-regular file: %s", rulepkg.InstallSourceSpecialFile.ID, rel)
		}
		if srcInfo.Size() > installMaxCopyFileBytes {
			return fmt.Errorf("%s: install source file exceeds size limit: %s", rulepkg.InstallSourceFileTooLarge.ID, rel)
		}
		files++
		if files > installMaxCopyFiles {
			return fmt.Errorf("%s: install source exceeds max file count: %d", rulepkg.InstallSourceFileCountExceeded.ID, installMaxCopyFiles)
		}
		remainingTotal := installMaxCopyTotalBytes - totalBytes
		if remainingTotal <= 0 {
			return fmt.Errorf("%s: install source exceeds max total bytes: %d", rulepkg.InstallSourceTotalBytesExceeded.ID, installMaxCopyTotalBytes)
		}
		if srcInfo.Size() > remainingTotal {
			return fmt.Errorf("%s: install source exceeds max total bytes: %d", rulepkg.InstallSourceTotalBytesExceeded.ID, installMaxCopyTotalBytes)
		}
		maxCopyBytes := installMaxCopyFileBytes
		if remainingTotal < maxCopyBytes {
			maxCopyBytes = remainingTotal
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("failed to create install directory: %w", err)
		}
		written, err := limitio.CopyFileWithModeChecked(path, destPath, 0o644, maxCopyBytes, srcInfo, ensureInstallSourceStableFromOpen)
		if err != nil {
			if limitio.IsSizeExceeded(err) {
				return fmt.Errorf("%s: install source file exceeds size limit during copy: %s", rulepkg.InstallSourceFileTooLarge.ID, path)
			}
			if strings.HasPrefix(err.Error(), "failed to open source file") ||
				strings.HasPrefix(err.Error(), "failed to create destination file") ||
				strings.Contains(err.Error(), rulepkg.InstallSourceChangedDuringCopy.ID) {
				return err
			}
			if !strings.HasPrefix(err.Error(), "failed to copy file contents") {
				return fmt.Errorf("failed to copy file contents: %w", err)
			}
			return err
		}
		totalBytes += written
		return nil
	})
}

func writeInstallMetadata(stagedSkill string, report installReport) error {
	if report.Source.Kind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(report.Source.Input)
		if err != nil {
			return fmt.Errorf("invalid github source while writing source metadata: %w", err)
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return fmt.Errorf("github source metadata requires commit-pinned ref")
		}
		_, rootHash, err := buildFileDigestsFiltered(stagedSkill, map[string]struct{}{
			sourceMetadataFile: {},
			installReportFile:  {},
			installLockFile:    {},
		})
		if err != nil {
			return err
		}
		if err := writeSourceMetadata(stagedSkill, sourceMetadata{
			Schema:          sourceMetadataSchemaVersion,
			SourceInput:     report.Source.Input,
			SourceKind:      report.Source.Kind,
			ResolvedRef:     spec.Ref,
			FetchedAt:       time.Now().UTC().Format(time.RFC3339),
			SkillRootSHA256: rootHash,
		}); err != nil {
			return err
		}
	}

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render install report: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagedSkill, installReportFile), reportBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write install report: %w", err)
	}

	lock, err := buildInstallLock(stagedSkill, report)
	if err != nil {
		return err
	}
	lockBytes, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to render install lockfile: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stagedSkill, installLockFile), lockBytes, 0o644); err != nil {
		return fmt.Errorf("failed to write install lockfile: %w", err)
	}
	return nil
}

func buildInstallLock(stagedSkill string, report installReport) (installLock, error) {
	files, rootHash, err := buildFileDigestsForLock(stagedSkill)
	if err != nil {
		return installLock{}, err
	}

	summary := lockFindingSummary{}
	for _, finding := range report.Findings {
		switch finding.Severity {
		case policypkg.SeverityCritical:
			summary.Critical++
		case policypkg.SeverityHigh:
			summary.High++
		case policypkg.SeverityMedium:
			summary.Medium++
		case policypkg.SeverityLow:
			summary.Low++
		}
	}

	skillName := filepath.Base(filepath.Clean(stagedSkill))
	return installLock{
		Schema:      lockSchemaVersion,
		Name:        skillName,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Source: lockSource{
			Type:  sourceTypeFromKind(report.Source.Kind),
			Input: report.Source.Input,
			Kind:  report.Source.Kind,
		},
		Skill: lockSkill{
			RootSHA256: rootHash,
			Files:      files,
		},
		Policy: lockPolicy{
			Profile:           report.PolicyProfile,
			Decision:          strings.ToLower(report.Decision),
			SeverityOverrides: []policypkg.SeverityOverrideAudit(policypkg.SeverityOverrideAuditSet(report.SeverityOverrides).Clone()),
		},
		Findings: summary,
	}, nil
}

func sourceTypeFromKind(kind string) string {
	switch kind {
	case "local-dir":
		return "local"
	case "zip", "tar":
		return "archive"
	case "github-source":
		return "github"
	default:
		return "unknown"
	}
}
