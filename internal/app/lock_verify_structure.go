package app

import (
	"fmt"
	"strings"
	"time"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func verifyLockStructure(lock installLock) (bool, string) {
	trimmedName := strings.TrimSpace(lock.Name)
	if strings.IndexFunc(lock.Name, isC0OrC1ControlRune) >= 0 {
		return false, "lock name must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Name) {
		return false, "lock name must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedName == "" {
		return false, "lock name is empty"
	}
	if trimmedName != lock.Name {
		return false, "lock name must not contain leading or trailing whitespace"
	}

	trimmedInstalledAt := strings.TrimSpace(lock.InstalledAt)
	if strings.IndexFunc(lock.InstalledAt, isC0OrC1ControlRune) >= 0 {
		return false, "lock installed_at must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.InstalledAt) {
		return false, "lock installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedInstalledAt == "" {
		return false, "lock installed_at is empty"
	}
	if trimmedInstalledAt != lock.InstalledAt {
		return false, "lock installed_at must not contain leading or trailing whitespace"
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return false, "lock installed_at must be RFC3339"
	}

	trimmedProfile := strings.TrimSpace(lock.Policy.Profile)
	if strings.IndexFunc(lock.Policy.Profile, isC0OrC1ControlRune) >= 0 {
		return false, "lock policy profile must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Profile) {
		return false, "lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedProfile == "" {
		return false, "lock policy profile is empty"
	}
	normalizedProfile := policypkg.NormalizeProfile(trimmedProfile)
	if lock.Policy.Profile != normalizedProfile.String() {
		return false, "lock policy profile must be canonical lowercase without surrounding whitespace"
	}
	if _, err := policypkg.ParseProfile(normalizedProfile.String()); err != nil {
		return false, fmt.Sprintf("lock policy profile is unsupported: %s", lock.Policy.Profile)
	}
	trimmedDecision := strings.TrimSpace(lock.Policy.Decision)
	if strings.IndexFunc(lock.Policy.Decision, isC0OrC1ControlRune) >= 0 {
		return false, "lock policy decision must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Policy.Decision) {
		return false, "lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedDecision != lock.Policy.Decision {
		return false, "lock policy decision must not contain leading or trailing whitespace"
	}
	if lock.Policy.Decision != "pass" {
		return false, fmt.Sprintf("lock policy decision must be canonical lowercase pass for installed skill, got %s", lock.Policy.Decision)
	}
	if err := policypkg.SeverityOverrideAuditSet(lock.Policy.SeverityOverrides).Validate(); err != nil {
		return false, fmt.Sprintf("lock policy severity_overrides is invalid: %v", err)
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return false, fmt.Sprintf("lock findings summary is invalid: %v", err)
	}

	if !isCanonicalSHA256Hex(lock.Skill.RootSHA256) {
		return false, "lock skill root_sha256 must be a canonical lowercase 64-char hex digest"
	}
	if len(lock.Skill.Files) == 0 {
		return false, "lock skill files is empty"
	}

	seen := make(map[string]struct{}, len(lock.Skill.Files))
	for _, file := range lock.Skill.Files {
		if strings.IndexFunc(file.Path, isC0OrC1ControlRune) >= 0 {
			return false, fmt.Sprintf("lock file path is invalid: %s", file.Path)
		}
		if strings.TrimSpace(file.Path) == "" {
			return false, "lock file path is empty"
		}
		if !isValidLockRelativePath(file.Path) {
			return false, fmt.Sprintf("lock file path is invalid: %s", file.Path)
		}
		if _, exists := seen[file.Path]; exists {
			return false, fmt.Sprintf("duplicate lock file path: %s", file.Path)
		}
		seen[file.Path] = struct{}{}

		if !isCanonicalSHA256Hex(file.SHA256) {
			return false, fmt.Sprintf("lock file sha256 is invalid: %s", file.Path)
		}
		if file.Bytes < 0 {
			return false, fmt.Sprintf("lock file bytes is negative: %s", file.Path)
		}
	}

	return true, fmt.Sprintf("installed_at=%s files=%d", lock.InstalledAt, len(lock.Skill.Files))
}
