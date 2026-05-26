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
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

const sourceMetadataFile = ".gokui-source.json"

var maxSourceMetadataFileBytes int64 = 1_000_000

const ruleSourceMetadataFileTooLarge = "SOURCE_METADATA_FILE_TOO_LARGE"
const ruleSourceMetadataSymlink = "SOURCE_METADATA_SYMLINK_DETECTED"
const ruleSourceMetadataSpecialFile = "SOURCE_METADATA_SPECIAL_FILE"
const ruleSourceMetadataSourceChanged = "SOURCE_METADATA_SOURCE_CHANGED_DURING_READ"
const ruleSourceMetadataInvalidUTF8 = "SOURCE_METADATA_INVALID_UTF8"

type sourceMetadata struct {
	Schema          string `json:"schema"`
	SourceInput     string `json:"source_input"`
	SourceKind      string `json:"source_kind"`
	ResolvedRef     string `json:"resolved_ref"`
	FetchedAt       string `json:"fetched_at"`
	SkillRootSHA256 string `json:"skill_root_sha256"`
}

func writeSourceMetadata(skillRoot string, meta sourceMetadata) error {
	raw, _ := json.MarshalIndent(meta, "", "  ")
	path := filepath.Join(skillRoot, sourceMetadataFile)
	if err := rejectSymlinkPath(path, "source metadata file", ruleSourceMetadataSymlink); err != nil {
		return err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: source metadata file must not be a symlink: %s", ruleSourceMetadataSymlink, path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: source metadata file must be a regular file: %s", ruleSourceMetadataSpecialFile, path)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("failed to evaluate source metadata file: %w", statErr)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("failed to write source metadata: %w", err)
	}
	return nil
}

func readSourceMetadata(skillRoot string) (sourceMetadata, bool, error) {
	path := filepath.Join(skillRoot, sourceMetadataFile)
	if err := rejectSymlinkPath(path, "source metadata file", ruleSourceMetadataSymlink); err != nil {
		return sourceMetadata{}, false, err
	}
	linkInfo, lstatErr := os.Lstat(path)
	if lstatErr != nil {
		if os.IsNotExist(lstatErr) {
			return sourceMetadata{}, false, nil
		}
		return sourceMetadata{}, false, fmt.Errorf("failed to read source metadata: %w", lstatErr)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return sourceMetadata{}, false, fmt.Errorf("%s: source metadata file must not be a symlink: %s", ruleSourceMetadataSymlink, path)
	}
	if !linkInfo.Mode().IsRegular() {
		return sourceMetadata{}, false, fmt.Errorf("%s: source metadata file must be a regular file: %s", ruleSourceMetadataSpecialFile, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return sourceMetadata{}, false, fmt.Errorf("failed to read source metadata: %w", err)
	}
	defer f.Close()
	currentInfo, statErr := f.Stat()
	if statErr != nil {
		return sourceMetadata{}, false, fmt.Errorf("failed to read source metadata: %w", statErr)
	}
	if err := ensureSourceMetadataStableFile(linkInfo, currentInfo, path); err != nil {
		return sourceMetadata{}, false, err
	}

	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxSourceMetadataFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return sourceMetadata{}, false, fmt.Errorf("%s: source metadata exceeds size limit: %s", ruleSourceMetadataFileTooLarge, path)
		}
		return sourceMetadata{}, false, fmt.Errorf("failed to read source metadata: %w", err)
	}
	if !utf8.Valid(raw.Bytes()) {
		return sourceMetadata{}, false, fmt.Errorf("%s: source metadata must be valid UTF-8: %s", ruleSourceMetadataInvalidUTF8, path)
	}

	var meta sourceMetadata
	if err := json.Unmarshal(raw.Bytes(), &meta); err != nil {
		return sourceMetadata{}, false, fmt.Errorf("invalid source metadata JSON: %w", err)
	}
	if err := validateSourceMetadata(meta); err != nil {
		return sourceMetadata{}, false, err
	}
	return meta, true, nil
}

func ensureSourceMetadataStableFile(previous os.FileInfo, current os.FileInfo, path string) error {
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: source metadata file changed during read: %s", ruleSourceMetadataSourceChanged, path)
}

func validateSourceMetadata(meta sourceMetadata) error {
	if strings.IndexFunc(meta.Schema, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata schema must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.Schema) {
		return fmt.Errorf("source metadata schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if strings.TrimSpace(meta.Schema) != meta.Schema {
		return fmt.Errorf("source metadata schema must not contain leading or trailing whitespace")
	}
	if meta.Schema != sourceMetadataSchemaVersion {
		return fmt.Errorf("unsupported source metadata schema: %s", meta.Schema)
	}
	trimmedSourceInput := strings.TrimSpace(meta.SourceInput)
	if trimmedSourceInput == "" {
		return fmt.Errorf("source metadata source_input is empty")
	}
	if strings.IndexFunc(meta.SourceInput, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata source_input must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.SourceInput) {
		return fmt.Errorf("source metadata source_input must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if trimmedSourceInput != meta.SourceInput {
		return fmt.Errorf("source metadata source_input must not contain leading or trailing whitespace")
	}
	if strings.IndexFunc(meta.SourceKind, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata source_kind must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.SourceKind) {
		return fmt.Errorf("source metadata source_kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	trimmedSourceKind := strings.TrimSpace(meta.SourceKind)
	if trimmedSourceKind == "" {
		return fmt.Errorf("source metadata source_kind is empty")
	}
	if trimmedSourceKind != meta.SourceKind {
		return fmt.Errorf("source metadata source_kind must not contain leading or trailing whitespace")
	}
	if trimmedSourceKind != strings.ToLower(trimmedSourceKind) {
		return fmt.Errorf("source metadata source_kind must be canonical lowercase")
	}
	if trimmedSourceKind != "github-source" {
		return fmt.Errorf("source metadata source_kind is unsupported: %s", meta.SourceKind)
	}
	spec, err := srcpkg.ParseGitHubSource(meta.SourceInput)
	if err != nil {
		return fmt.Errorf("source metadata has invalid github source input: %w", err)
	}
	if meta.SourceInput != canonicalGitHubSourceInput(spec) {
		return fmt.Errorf("source metadata source_input must be canonical")
	}
	if !srcpkg.IsCommitPinnedRef(spec.Ref) {
		return fmt.Errorf("source metadata requires commit-pinned github ref")
	}
	if strings.IndexFunc(meta.ResolvedRef, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata resolved_ref must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.ResolvedRef) {
		return fmt.Errorf("source metadata resolved_ref must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	trimmedResolvedRef := strings.TrimSpace(meta.ResolvedRef)
	if trimmedResolvedRef == "" {
		return fmt.Errorf("source metadata resolved_ref is empty")
	}
	if trimmedResolvedRef != meta.ResolvedRef {
		return fmt.Errorf("source metadata resolved_ref must not contain leading or trailing whitespace")
	}
	if trimmedResolvedRef != strings.ToLower(trimmedResolvedRef) {
		return fmt.Errorf("source metadata resolved_ref must be canonical lowercase")
	}
	if !srcpkg.IsCommitPinnedRef(meta.ResolvedRef) {
		return fmt.Errorf("source metadata resolved_ref must be commit-pinned")
	}
	if spec.Ref != meta.ResolvedRef {
		return fmt.Errorf("source metadata resolved_ref does not match source_input ref")
	}
	if strings.IndexFunc(meta.FetchedAt, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata fetched_at must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.FetchedAt) {
		return fmt.Errorf("source metadata fetched_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	trimmedFetchedAt := strings.TrimSpace(meta.FetchedAt)
	if trimmedFetchedAt == "" {
		return fmt.Errorf("source metadata fetched_at is empty")
	}
	if trimmedFetchedAt != meta.FetchedAt {
		return fmt.Errorf("source metadata fetched_at must not contain leading or trailing whitespace")
	}
	if _, err := time.Parse(time.RFC3339, trimmedFetchedAt); err != nil {
		return fmt.Errorf("source metadata fetched_at must be RFC3339")
	}
	if strings.IndexFunc(meta.SkillRootSHA256, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("source metadata skill_root_sha256 must not contain C0/C1 control characters")
	}
	if containsSeverityOverrideDisallowedUnicode(meta.SkillRootSHA256) {
		return fmt.Errorf("source metadata skill_root_sha256 must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
	}
	if strings.TrimSpace(meta.SkillRootSHA256) == "" {
		return fmt.Errorf("source metadata skill_root_sha256 is empty")
	}
	rootHash := strings.TrimSpace(meta.SkillRootSHA256)
	if rootHash != meta.SkillRootSHA256 {
		return fmt.Errorf("source metadata skill_root_sha256 must not contain leading or trailing whitespace")
	}
	if !isCanonicalSHA256Hex(rootHash) {
		return fmt.Errorf("source metadata skill_root_sha256 must be a canonical lowercase 64-char hex digest")
	}
	return nil
}

func resolveSourceForInstall(skillRoot string, fallbackInput string, fallbackKind string) (source, error) {
	// Only GitHub-origin installs should consume .gokui-source.json provenance.
	// For local/archive inputs, metadata files inside untrusted bundles must not
	// override the user-provided source identity.
	if fallbackKind != "github-source" {
		return source{Input: fallbackInput, Kind: fallbackKind}, nil
	}

	meta, ok, err := readSourceMetadata(skillRoot)
	if err != nil {
		return source{}, err
	}
	if !ok {
		return source{Input: fallbackInput, Kind: fallbackKind}, nil
	}
	if meta.SourceInput != fallbackInput || meta.SourceKind != fallbackKind {
		return source{}, fmt.Errorf("source metadata mismatch with install source")
	}

	_, actualRoot, err := buildFileDigestsFiltered(skillRoot, map[string]struct{}{
		sourceMetadataFile: {},
	})
	if err != nil {
		return source{}, err
	}
	if meta.SkillRootSHA256 != actualRoot {
		return source{}, fmt.Errorf("source metadata hash mismatch: expected %s, got %s", meta.SkillRootSHA256, actualRoot)
	}
	return source{
		Input: meta.SourceInput,
		Kind:  meta.SourceKind,
	}, nil
}

func verifyInstalledSourceMetadata(skillPath string, lockSource source) error {
	meta, ok, err := readSourceMetadata(skillPath)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("missing source metadata: %s", sourceMetadataFile)
	}
	if meta.SourceInput != lockSource.Input || meta.SourceKind != lockSource.Kind {
		return fmt.Errorf("source metadata mismatch with lock source")
	}
	_, actualRoot, err := buildFileDigestsFiltered(skillPath, map[string]struct{}{
		sourceMetadataFile: {},
		installReportFile:  {},
		installLockFile:    {},
	})
	if err != nil {
		return err
	}
	if meta.SkillRootSHA256 != actualRoot {
		return fmt.Errorf("installed source metadata hash mismatch")
	}
	return nil
}
