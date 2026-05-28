package app

import (
	"fmt"
	"path/filepath"
	"strings"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func verifyLockSource(lock installLock) (bool, string) {
	trimmedKind := strings.TrimSpace(lock.Source.Kind)
	if strings.IndexFunc(lock.Source.Kind, isC0OrC1ControlRune) >= 0 {
		return false, "lock source kind must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Kind) {
		return false, "lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedKind == "" {
		return false, "lock source kind is empty"
	}
	if trimmedKind != lock.Source.Kind {
		return false, "lock source kind must not contain leading or trailing whitespace"
	}
	if trimmedKind != strings.ToLower(trimmedKind) {
		return false, "lock source kind must be canonical lowercase"
	}
	trimmedInput := strings.TrimSpace(lock.Source.Input)
	if strings.IndexFunc(lock.Source.Input, isC0OrC1ControlRune) >= 0 {
		return false, "lock source input must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Input) {
		return false, "lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedInput == "" {
		return false, "lock source input is empty"
	}
	if trimmedInput != lock.Source.Input {
		return false, "lock source input must not contain leading or trailing whitespace"
	}
	detectedKind := detectSourceKind(trimmedInput)
	if trimmedKind != detectedKind {
		return false, fmt.Sprintf("lock source kind does not match source input: kind=%s detected=%s", trimmedKind, detectedKind)
	}

	expectedType := sourceTypeFromKind(trimmedKind)
	if expectedType == "unknown" {
		return false, fmt.Sprintf("unsupported lock source kind: %s", trimmedKind)
	}
	if expectedType != "github" {
		cleanedInput := filepath.Clean(trimmedInput)
		if trimmedInput != cleanedInput {
			return false, "lock source input must be a canonical cleaned path for local/archive sources"
		}
	}
	trimmedType := strings.TrimSpace(lock.Source.Type)
	if strings.IndexFunc(lock.Source.Type, isC0OrC1ControlRune) >= 0 {
		return false, "lock source type must not contain C0/C1 control characters"
	}
	if containsSeverityOverrideDisallowedUnicode(lock.Source.Type) {
		return false, "lock source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	}
	if trimmedType == "" {
		return false, "lock source type is empty"
	}
	if trimmedType != lock.Source.Type {
		return false, "lock source type must not contain leading or trailing whitespace"
	}
	if trimmedType != strings.ToLower(trimmedType) {
		return false, "lock source type must be canonical lowercase"
	}
	if trimmedType != expectedType {
		return false, fmt.Sprintf("source type mismatch for kind %s: expected %s, got %s", trimmedKind, expectedType, trimmedType)
	}

	if trimmedKind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(trimmedInput)
		if err != nil {
			return false, fmt.Sprintf("invalid github source input in lock: %v", err)
		}
		if trimmedInput != canonicalGitHubSourceInput(spec) {
			return false, "github lock source input must be canonical"
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return false, "github lock source must be commit-pinned"
		}
	}
	return true, fmt.Sprintf("kind=%s type=%s", trimmedKind, trimmedType)
}

func verifyLockSourceMetadata(skillPath string, lock installLock) (bool, string) {
	if lock.Source.Kind != "github-source" {
		return true, fmt.Sprintf("not required for source kind %s", lock.Source.Kind)
	}

	err := verifyInstalledSourceMetadata(skillPath, source{
		Input: lock.Source.Input,
		Kind:  lock.Source.Kind,
	})
	if err != nil {
		return false, err.Error()
	}
	return true, "metadata matches lock source and installed hash"
}
