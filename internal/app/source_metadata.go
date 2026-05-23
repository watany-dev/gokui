package app

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

const sourceMetadataFile = ".gokui-source.json"

var maxSourceMetadataFileBytes int64 = 1_000_000

const ruleSourceMetadataFileTooLarge = "SOURCE_METADATA_FILE_TOO_LARGE"
const ruleSourceMetadataSymlink = "SOURCE_METADATA_SYMLINK_DETECTED"

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
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("failed to write source metadata: %w", err)
	}
	return nil
}

func readSourceMetadata(skillRoot string) (sourceMetadata, bool, error) {
	path := filepath.Join(skillRoot, sourceMetadataFile)
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
	if linkInfo.Size() > maxSourceMetadataFileBytes {
		return sourceMetadata{}, false, fmt.Errorf("%s: source metadata exceeds size limit: %s", ruleSourceMetadataFileTooLarge, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return sourceMetadata{}, false, fmt.Errorf("failed to read source metadata: %w", err)
	}

	var meta sourceMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return sourceMetadata{}, false, fmt.Errorf("invalid source metadata JSON: %w", err)
	}
	if err := validateSourceMetadata(meta); err != nil {
		return sourceMetadata{}, false, err
	}
	return meta, true, nil
}

func validateSourceMetadata(meta sourceMetadata) error {
	if meta.Schema != sourceMetadataSchemaVersion {
		return fmt.Errorf("unsupported source metadata schema: %s", meta.Schema)
	}
	if strings.TrimSpace(meta.SourceInput) == "" {
		return fmt.Errorf("source metadata source_input is empty")
	}
	if meta.SourceKind != "github-source" {
		return fmt.Errorf("source metadata source_kind is unsupported: %s", meta.SourceKind)
	}
	spec, err := srcpkg.ParseGitHubSource(meta.SourceInput)
	if err != nil {
		return fmt.Errorf("source metadata has invalid github source input: %w", err)
	}
	if !srcpkg.IsCommitPinnedRef(spec.Ref) {
		return fmt.Errorf("source metadata requires commit-pinned github ref")
	}
	if strings.TrimSpace(meta.ResolvedRef) == "" {
		return fmt.Errorf("source metadata resolved_ref is empty")
	}
	if !srcpkg.IsCommitPinnedRef(meta.ResolvedRef) {
		return fmt.Errorf("source metadata resolved_ref must be commit-pinned")
	}
	if !strings.EqualFold(strings.TrimSpace(spec.Ref), strings.TrimSpace(meta.ResolvedRef)) {
		return fmt.Errorf("source metadata resolved_ref does not match source_input ref")
	}
	if strings.TrimSpace(meta.FetchedAt) == "" {
		return fmt.Errorf("source metadata fetched_at is empty")
	}
	if _, err := time.Parse(time.RFC3339, meta.FetchedAt); err != nil {
		return fmt.Errorf("source metadata fetched_at must be RFC3339")
	}
	if strings.TrimSpace(meta.SkillRootSHA256) == "" {
		return fmt.Errorf("source metadata skill_root_sha256 is empty")
	}
	rootHash := strings.TrimSpace(meta.SkillRootSHA256)
	decoded, err := hex.DecodeString(rootHash)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("source metadata skill_root_sha256 must be a 64-char hex digest")
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
