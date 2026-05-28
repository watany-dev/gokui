package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
)

func verifyInstallReport(skillPath string, lock installLock) (bool, string) {
	reportPath := filepath.Join(skillPath, installReportFile)
	if err := rejectSymlinkPath(reportPath, "install report file", rulepkg.InstallReportSymlink.ID); err != nil {
		return false, err.Error()
	}
	linkInfo, lstatErr := os.Lstat(reportPath)
	if lstatErr != nil {
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Sprintf("%s: install report file must not be a symlink: %s", rulepkg.InstallReportSymlink.ID, reportPath)
	}
	if !linkInfo.Mode().IsRegular() {
		return false, fmt.Sprintf("%s: install report file must be a regular file: %s", rulepkg.InstallReportSpecialFile.ID, reportPath)
	}

	f, err := os.Open(reportPath)
	if err != nil {
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	defer f.Close()
	if err := ensureInstallReportStableFromOpen(linkInfo, f, reportPath); err != nil {
		return false, err.Error()
	}

	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxInstallReportFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return false, fmt.Sprintf("%s: install report exceeds size limit: %s", rulepkg.InstallReportTooLarge.ID, reportPath)
		}
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	if !utf8.Valid(raw.Bytes()) {
		return false, fmt.Sprintf("%s: install report must be valid UTF-8: %s", rulepkg.InstallReportInvalidUTF8.ID, reportPath)
	}

	var report installReport
	if err := json.Unmarshal(raw.Bytes(), &report); err != nil {
		return false, "invalid install report JSON"
	}
	trimmedSchemaVersion := strings.TrimSpace(report.SchemaVersion)
	if strings.IndexFunc(report.SchemaVersion, isC0OrC1ControlRune) >= 0 {
		return false, "install report schema_version must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.SchemaVersion) {
		return false, "install report schema_version must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedSchemaVersion == "" {
		return false, "install report schema_version is empty"
	}
	if trimmedSchemaVersion != report.SchemaVersion {
		return false, "install report schema_version must not contain leading or trailing whitespace"
	}
	if report.SchemaVersion != reportSchemaVersion {
		return false, fmt.Sprintf("install report schema_version is unsupported: %s", report.SchemaVersion)
	}
	trimmedSourceInput := strings.TrimSpace(report.Source.Input)
	if strings.IndexFunc(report.Source.Input, isC0OrC1ControlRune) >= 0 {
		return false, "install report source input must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.Source.Input) {
		return false, "install report source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedSourceInput == "" {
		return false, "install report source input is empty"
	}
	if trimmedSourceInput != report.Source.Input {
		return false, "install report source input must not contain leading or trailing whitespace"
	}
	trimmedSourceKind := strings.TrimSpace(report.Source.Kind)
	if strings.IndexFunc(report.Source.Kind, isC0OrC1ControlRune) >= 0 {
		return false, "install report source kind must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.Source.Kind) {
		return false, "install report source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedSourceKind == "" {
		return false, "install report source kind is empty"
	}
	if trimmedSourceKind != report.Source.Kind {
		return false, "install report source kind must not contain leading or trailing whitespace"
	}
	if report.Source.Input != lock.Source.Input || report.Source.Kind != lock.Source.Kind {
		return false, "install report source does not match lock source"
	}
	trimmedPolicyProfile := strings.TrimSpace(report.PolicyProfile)
	if strings.IndexFunc(report.PolicyProfile, isC0OrC1ControlRune) >= 0 {
		return false, "install report policy profile must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.PolicyProfile) {
		return false, "install report policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedPolicyProfile == "" {
		return false, "install report policy profile is empty"
	}
	if trimmedPolicyProfile != report.PolicyProfile {
		return false, "install report policy profile must not contain leading or trailing whitespace"
	}
	if policypkg.NormalizeProfile(report.PolicyProfile).String() != report.PolicyProfile {
		return false, "install report policy profile must be canonical lowercase without surrounding whitespace"
	}
	if report.PolicyProfile != lock.Policy.Profile {
		return false, "install report policy profile does not match lock policy"
	}
	trimmedDecision := strings.TrimSpace(report.Decision)
	if strings.IndexFunc(report.Decision, isC0OrC1ControlRune) >= 0 {
		return false, "install report decision must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.Decision) {
		return false, "install report decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedDecision == "" {
		return false, "install report decision is empty"
	}
	if trimmedDecision != report.Decision {
		return false, "install report decision must not contain leading or trailing whitespace"
	}
	if !strings.EqualFold(report.Decision, lock.Policy.Decision) {
		return false, "install report decision does not match lock policy decision"
	}
	if err := policypkg.SeverityOverrideAuditSet(report.SeverityOverrides).Validate(); err != nil {
		return false, fmt.Sprintf("install report severity_overrides is invalid: %v", err)
	}
	if !policypkg.SeverityOverrideAuditSet(report.SeverityOverrides).Equal(policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides)) {
		return false, "install report severity_overrides does not match lock policy severity_overrides"
	}
	if !strings.EqualFold(report.Decision, "pass") {
		return false, "install report decision must be pass for installed skill"
	}
	if !report.Installed {
		return false, "install report installed must be true"
	}
	trimmedInstalledPath := strings.TrimSpace(report.InstalledPath)
	if strings.IndexFunc(report.InstalledPath, isC0OrC1ControlRune) >= 0 {
		return false, "install report installed path must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(report.InstalledPath) {
		return false, "install report installed path must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedInstalledPath == "" {
		return false, "install report installed path is empty"
	}
	if trimmedInstalledPath != report.InstalledPath {
		return false, "install report installed path must not contain leading or trailing whitespace"
	}
	if filepath.Clean(report.InstalledPath) != filepath.Clean(skillPath) {
		return false, fmt.Sprintf("install report path mismatch: expected %s, got %s", skillPath, report.InstalledPath)
	}

	reportSummary := summarizeFindingSeverities(report.Findings)
	if reportSummary != lock.Findings {
		return false, "install report findings summary does not match lock findings"
	}

	return true, fmt.Sprintf("schema=%s decision=%s", report.SchemaVersion, report.Decision)
}

func ensureInstallReportStableFromOpen(previous os.FileInfo, opened fileInfoStatter, reportPath string) error {
	return safefs.CheckOpenedStable(previous, opened, reportPath,
		func(path string) error {
			return fmt.Errorf("failed to read install report: %s", path)
		},
		func(path string) error {
			return fmt.Errorf("%s: install report file changed during read: %s", rulepkg.InstallReportSourceChangedDuringRead.ID, path)
		},
	)
}
