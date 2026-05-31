package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/watany-dev/gokui/internal/limitio"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func loadPersistedInstallReport(skillPath string) (installReport, error) {
	reportPath := filepath.Join(skillPath, installReportFile)
	if err := rejectSymlinkPath(reportPath, "install report file", rulepkg.InstallReportSymlink.ID); err != nil {
		return installReport{}, err
	}
	info, err := os.Lstat(reportPath)
	if err != nil {
		return installReport{}, fmt.Errorf("failed to read install report: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return installReport{}, fmt.Errorf("%s: install report file must not be a symlink: %s", rulepkg.InstallReportSymlink.ID, reportPath)
	}
	if !info.Mode().IsRegular() {
		return installReport{}, fmt.Errorf("%s: install report file must be a regular file: %s", rulepkg.InstallReportSpecialFile.ID, reportPath)
	}

	f, err := os.Open(reportPath)
	if err != nil {
		return installReport{}, fmt.Errorf("failed to read install report: %w", err)
	}
	defer f.Close()

	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxInstallReportFileBytes); err != nil {
		return installReport{}, fmt.Errorf("failed to read install report: %w", err)
	}

	var report installReport
	if err := json.Unmarshal(raw.Bytes(), &report); err != nil {
		return installReport{}, fmt.Errorf("invalid install report JSON: %w", err)
	}
	return report, nil
}

func resolveInstallOutputReport(installedPath string, installResult installResult, evaluated installReport) installReport {
	report := evaluated
	report.Installed = true
	report.InstalledPath = installedPath
	if installResult == installResultAlreadyInstalled {
		if persisted, loadErr := loadPersistedInstallReport(installedPath); loadErr == nil {
			report = persisted
			report.Installed = true
			report.InstalledPath = installedPath
		}
	}
	return report
}
