package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func readInstallLock(path string) (installLock, error) {
	return readInstallLockWithLimit(path, maxInstallLockFileBytes)
}

func readInstallLockWithLimit(path string, maxBytes int64) (installLock, error) {
	if err := rejectSymlinkPath(path, "install lockfile", rulepkg.LockfileSymlink.ID); err != nil {
		return installLock{}, err
	}
	linkInfo, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return installLock{}, fmt.Errorf("%s: install lockfile must not be a symlink: %s", rulepkg.LockfileSymlink.ID, path)
	}
	if !linkInfo.Mode().IsRegular() {
		return installLock{}, fmt.Errorf("%s: install lockfile must be a regular file: %s", rulepkg.LockfileSpecialFile.ID, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	defer f.Close()
	if err := ensureInstallLockStableFromOpen(linkInfo, f, path); err != nil {
		return installLock{}, err
	}
	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return installLock{}, fmt.Errorf("%s: install lockfile exceeds size limit: %s", rulepkg.LockfileTooLarge.ID, path)
		}
		return installLock{}, fmt.Errorf("failed to read install lockfile: %s", path)
	}
	if !utf8.Valid(raw.Bytes()) {
		return installLock{}, fmt.Errorf("%s: install lockfile must be valid UTF-8: %s", rulepkg.LockfileInvalidUTF8.ID, path)
	}

	var lock installLock
	if err := json.Unmarshal(raw.Bytes(), &lock); err != nil {
		return installLock{}, fmt.Errorf("invalid install lockfile JSON: %s", path)
	}
	if strings.IndexFunc(lock.Schema, isC0OrC1ControlRune) >= 0 {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain C0/C1 control characters at %s: %s", path, lock.Schema)
	}
	if strings.TrimSpace(lock.Schema) != lock.Schema {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain leading or trailing whitespace at %s: %s", path, lock.Schema)
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Schema) {
		return installLock{}, fmt.Errorf("install lockfile schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters at %s: %s", path, lock.Schema)
	}
	if lock.Schema != lockSchemaVersion {
		return installLock{}, fmt.Errorf("unsupported install lockfile schema at %s: %s", path, lock.Schema)
	}
	return lock, nil
}

func ensureInstallLockStableFromOpen(previous os.FileInfo, opened fileInfoStatter, path string) error {
	return safefs.CheckOpenedStable(previous, opened, path,
		func(path string) error {
			return fmt.Errorf("failed to read install lockfile: %s", path)
		},
		func(path string) error {
			return fmt.Errorf("%s: install lockfile changed during read: %s", rulepkg.LockfileSourceChangedDuringRead.ID, path)
		},
	)
}

func provenanceMatches(existing installLock, incoming installLock) bool {
	if existing.Schema != incoming.Schema {
		return false
	}
	if existing.Name != incoming.Name {
		return false
	}
	if existing.Source != incoming.Source {
		return false
	}
	if existing.Policy.Profile != incoming.Policy.Profile {
		return false
	}
	if existing.Skill.RootSHA256 != incoming.Skill.RootSHA256 {
		return false
	}
	return true
}

func validateInstallLockForProvenanceReuse(lock installLock, expectedSkillName string) error {
	if strings.IndexFunc(lock.Schema, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock schema must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Schema) {
		return fmt.Errorf("lock schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if strings.TrimSpace(lock.Schema) != lock.Schema {
		return fmt.Errorf("lock schema must not contain leading or trailing whitespace")
	}
	if lock.Schema != lockSchemaVersion {
		return fmt.Errorf("unsupported install lock schema: %s", lock.Schema)
	}
	trimmedName := strings.TrimSpace(lock.Name)
	if strings.IndexFunc(lock.Name, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock name must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Name) {
		return fmt.Errorf("lock name must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedName == "" {
		return fmt.Errorf("lock name is empty")
	}
	if trimmedName != lock.Name {
		return fmt.Errorf("lock name must not contain leading or trailing whitespace")
	}
	if expectedSkillName != "" && lock.Name != expectedSkillName {
		return fmt.Errorf("lock name does not match target skill directory: lock=%s target=%s", lock.Name, expectedSkillName)
	}

	trimmedInstalledAt := strings.TrimSpace(lock.InstalledAt)
	if strings.IndexFunc(lock.InstalledAt, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock installed_at must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.InstalledAt) {
		return fmt.Errorf("lock installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedInstalledAt == "" {
		return fmt.Errorf("lock installed_at is empty")
	}
	if trimmedInstalledAt != lock.InstalledAt {
		return fmt.Errorf("lock installed_at must not contain leading or trailing whitespace")
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return fmt.Errorf("lock installed_at must be RFC3339")
	}

	trimmedProfile := strings.TrimSpace(lock.Policy.Profile)
	if strings.IndexFunc(lock.Policy.Profile, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy profile must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Profile) {
		return fmt.Errorf("lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedProfile == "" {
		return fmt.Errorf("lock policy profile is empty")
	}
	if policypkg.NormalizeProfile(trimmedProfile).String() != lock.Policy.Profile {
		return fmt.Errorf("lock policy profile must be canonical lowercase without surrounding whitespace")
	}
	if _, err := policypkg.ParseProfile(lock.Policy.Profile); err != nil {
		return fmt.Errorf("lock policy profile is unsupported: %s", lock.Policy.Profile)
	}
	trimmedDecision := strings.TrimSpace(lock.Policy.Decision)
	if strings.IndexFunc(lock.Policy.Decision, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock policy decision must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Decision) {
		return fmt.Errorf("lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedDecision != lock.Policy.Decision {
		return fmt.Errorf("lock policy decision must not contain leading or trailing whitespace")
	}
	if lock.Policy.Decision != "pass" {
		return fmt.Errorf("lock policy decision must be canonical lowercase pass")
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return fmt.Errorf("lock findings summary is invalid: %v", err)
	}
	if err := policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides).Validate(); err != nil {
		return fmt.Errorf("lock policy severity_overrides is invalid: %v", err)
	}

	trimmedKind := strings.TrimSpace(lock.Source.Kind)
	if strings.IndexFunc(lock.Source.Kind, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source kind must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Kind) {
		return fmt.Errorf("lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedKind == "" {
		return fmt.Errorf("lock source kind is empty")
	}
	if trimmedKind != lock.Source.Kind {
		return fmt.Errorf("lock source kind must not contain leading or trailing whitespace")
	}
	if trimmedKind != strings.ToLower(trimmedKind) {
		return fmt.Errorf("lock source kind must be canonical lowercase")
	}
	trimmedInput := strings.TrimSpace(lock.Source.Input)
	if strings.IndexFunc(lock.Source.Input, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source input must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Input) {
		return fmt.Errorf("lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedInput == "" {
		return fmt.Errorf("lock source input is empty")
	}
	if trimmedInput != lock.Source.Input {
		return fmt.Errorf("lock source input must not contain leading or trailing whitespace")
	}
	if detectSourceKind(trimmedInput) != trimmedKind {
		return fmt.Errorf("lock source kind does not match source input")
	}

	expectedType := sourceTypeFromKind(trimmedKind)
	if expectedType == "unknown" {
		return fmt.Errorf("unsupported lock source kind: %s", trimmedKind)
	}
	trimmedType := strings.TrimSpace(lock.Source.Type)
	if strings.IndexFunc(lock.Source.Type, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("lock source type must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Type) {
		return fmt.Errorf("lock source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedType == "" {
		return fmt.Errorf("lock source type is empty")
	}
	if trimmedType != lock.Source.Type {
		return fmt.Errorf("lock source type must not contain leading or trailing whitespace")
	}
	if trimmedType != strings.ToLower(trimmedType) {
		return fmt.Errorf("lock source type must be canonical lowercase")
	}
	if trimmedType != expectedType {
		return fmt.Errorf("source type mismatch for kind %s: expected %s, got %s", trimmedKind, expectedType, trimmedType)
	}

	if trimmedKind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(trimmedInput)
		if err != nil {
			return fmt.Errorf("invalid github source input in lock: %v", err)
		}
		if trimmedInput != canonicalGitHubSourceInput(spec) {
			return fmt.Errorf("github lock source input must be canonical")
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return fmt.Errorf("github lock source must be commit-pinned")
		}
	} else {
		if trimmedInput != filepath.Clean(trimmedInput) {
			return fmt.Errorf("lock source input must be a canonical cleaned path for local/archive sources")
		}
	}

	if !isCanonicalSHA256Hex(lock.Skill.RootSHA256) {
		return fmt.Errorf("lock skill root_sha256 must be a canonical lowercase 64-char hex digest")
	}
	if len(lock.Skill.Files) == 0 {
		return fmt.Errorf("lock skill files is empty")
	}
	seen := make(map[string]struct{}, len(lock.Skill.Files))
	for _, file := range lock.Skill.Files {
		if strings.IndexFunc(file.Path, isC0OrC1ControlRune) >= 0 {
			return fmt.Errorf("lock file path is invalid: %s", file.Path)
		}
		if strings.TrimSpace(file.Path) == "" {
			return fmt.Errorf("lock file path is empty")
		}
		if !isValidLockRelativePath(file.Path) {
			return fmt.Errorf("lock file path is invalid: %s", file.Path)
		}
		if _, exists := seen[file.Path]; exists {
			return fmt.Errorf("duplicate lock file path: %s", file.Path)
		}
		seen[file.Path] = struct{}{}
		if !isCanonicalSHA256Hex(file.SHA256) {
			return fmt.Errorf("lock file sha256 is invalid: %s", file.Path)
		}
		if file.Bytes < 0 {
			return fmt.Errorf("lock file bytes is negative: %s", file.Path)
		}
	}

	return nil
}

func validateInstalledContentForIdempotentReuse(skillPath string, lock installLock) error {
	actualFiles, actualRootHash, err := buildFileDigestsForLock(skillPath)
	if err != nil {
		return fmt.Errorf("failed to verify installed skill content digests: %w", err)
	}
	missing, changed, unexpected := diffLockFiles(lock.Skill.Files, actualFiles)
	if len(missing) > 0 || len(changed) > 0 || len(unexpected) > 0 {
		return fmt.Errorf("installed skill content drift detected: missing=%d changed=%d unexpected=%d", len(missing), len(changed), len(unexpected))
	}
	if lock.Skill.RootSHA256 != actualRootHash {
		return fmt.Errorf("installed skill root hash drift detected: expected %s, got %s", lock.Skill.RootSHA256, actualRootHash)
	}
	if ok, detail := verifyInstallReport(skillPath, lock); !ok {
		return fmt.Errorf("install report integrity check failed: %s", detail)
	}
	if lock.Source.Kind == "github-source" {
		if err := verifyInstalledSourceMetadata(skillPath, source{
			Input: lock.Source.Input,
			Kind:  lock.Source.Kind,
		}); err != nil {
			return fmt.Errorf("installed github source metadata drift detected: %w", err)
		}
	}
	return nil
}
