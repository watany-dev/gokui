package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
)

func TestSourceMetadataHelpers(t *testing.T) {
	t.Run("read/write and resolve source", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "metadata-helper-skill")
		_, rootHash, err := buildFileDigestsFiltered(skillRoot, map[string]struct{}{
			sourceMetadataFile: {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		meta := sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/metadata-helper-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: rootHash,
		}
		if err := writeSourceMetadata(skillRoot, meta); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		got, ok, err := readSourceMetadata(skillRoot)
		if err != nil {
			t.Fatalf("readSourceMetadata() error = %v", err)
		}
		if !ok {
			t.Fatal("expected source metadata")
		}
		if got.SourceInput != meta.SourceInput {
			t.Fatalf("source_input = %q", got.SourceInput)
		}

		// Local installs must ignore embedded source metadata.
		resolved, err := resolveSourceForInstall(skillRoot, skillRoot, "local-dir")
		if err != nil {
			t.Fatalf("resolveSourceForInstall() error = %v", err)
		}
		if resolved.Kind != "local-dir" || resolved.Input != skillRoot {
			t.Fatalf("resolved source = %+v", resolved)
		}

		// GitHub installs may consume metadata only when it matches source input.
		resolved, err = resolveSourceForInstall(skillRoot, meta.SourceInput, "github-source")
		if err != nil {
			t.Fatalf("resolveSourceForInstall(github) error = %v", err)
		}
		if resolved.Kind != "github-source" || resolved.Input != meta.SourceInput {
			t.Fatalf("resolved github source = %+v", resolved)
		}

		if _, err := resolveSourceForInstall(skillRoot, "github:org/repo//skills/other@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source"); err == nil || !strings.Contains(err.Error(), "mismatch with install source") {
			t.Fatalf("expected metadata/source mismatch error, got %v", err)
		}
	})

	t.Run("read source metadata not found", func(t *testing.T) {
		dir := t.TempDir()
		_, ok, err := readSourceMetadata(dir)
		if err != nil {
			t.Fatalf("readSourceMetadata() error = %v", err)
		}
		if ok {
			t.Fatal("metadata should not exist")
		}
	})

	t.Run("read/write metadata error paths", func(t *testing.T) {
		nonDir := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(nonDir, []byte("x"), 0o644); err != nil {
			t.Fatalf("write nonDir file: %v", err)
		}
		if err := writeSourceMetadata(nonDir, sourceMetadata{}); err == nil {
			t.Fatal("expected write metadata error")
		}

		dirWithInvalid := t.TempDir()
		if err := os.WriteFile(filepath.Join(dirWithInvalid, sourceMetadataFile), []byte("{"), 0o644); err != nil {
			t.Fatalf("write invalid metadata file: %v", err)
		}
		if _, _, err := readSourceMetadata(dirWithInvalid); err == nil || !strings.Contains(err.Error(), "invalid source metadata JSON") {
			t.Fatalf("expected invalid json error, got %v", err)
		}

		dirAsMeta := t.TempDir()
		if err := os.Mkdir(filepath.Join(dirAsMeta, sourceMetadataFile), 0o755); err != nil {
			t.Fatalf("mkdir metadata directory: %v", err)
		}
		if _, _, err := readSourceMetadata(dirAsMeta); err == nil || !strings.Contains(err.Error(), "failed to read source metadata") {
			t.Fatalf("expected read error, got %v", err)
		}

		dirWithInvalidFields := t.TempDir()
		if err := os.WriteFile(filepath.Join(dirWithInvalidFields, sourceMetadataFile), []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
			t.Fatalf("write invalid-field metadata: %v", err)
		}
		if _, _, err := readSourceMetadata(dirWithInvalidFields); err == nil {
			t.Fatal("expected metadata validation error")
		}

		notDir := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
			t.Fatalf("write not-dir file: %v", err)
		}
		if _, _, err := readSourceMetadata(notDir); err == nil || !strings.Contains(err.Error(), "failed to read source metadata") {
			t.Fatalf("expected stat/read metadata error for non-directory root, got %v", err)
		}

		origLimit := maxSourceMetadataFileBytes
		maxSourceMetadataFileBytes = 8
		t.Cleanup(func() { maxSourceMetadataFileBytes = origLimit })
		oversizedDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(oversizedDir, sourceMetadataFile), []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
			t.Fatalf("write oversized metadata: %v", err)
		}
		if _, _, err := readSourceMetadata(oversizedDir); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataFileTooLarge) {
			t.Fatalf("expected oversized metadata error, got %v", err)
		}
	})

	t.Run("validate metadata errors", func(t *testing.T) {
		cases := []sourceMetadata{
			{},
			{
				Schema: "gokui.source/v1",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@main",
				SourceKind:  "github-source",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
				ResolvedRef: "main",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
				ResolvedRef: "abcdef0",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "not-a-time",
				SkillRootSHA256: "abc",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "zz",
			},
		}
		for _, c := range cases {
			if err := validateSourceMetadata(c); err == nil {
				t.Fatalf("expected validation error for %+v", c)
			}
		}
	})

	t.Run("validate metadata never panics on random inputs", func(t *testing.T) {
		prop := func(meta sourceMetadata) (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			_ = validateSourceMetadata(meta)
			return true
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("validateSourceMetadata panic-safety property failed: %v", err)
		}
	})

	t.Run("verify installed metadata errors", func(t *testing.T) {
		dir := t.TempDir()
		if err := verifyInstalledSourceMetadata(dir, source{Input: "x", Kind: "github-source"}); err == nil {
			t.Fatal("expected missing metadata error")
		}

		skillRoot := createSkillSourceForInstallTest(t, "verify-meta-skill")
		_, rootHash, err := buildFileDigestsFiltered(skillRoot, map[string]struct{}{
			sourceMetadataFile: {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		if err := writeSourceMetadata(skillRoot, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/verify-meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: rootHash,
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		if err := verifyInstalledSourceMetadata(skillRoot, source{
			Input: "github:org/repo//skills/verify-meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}); err != nil {
			t.Fatalf("verifyInstalledSourceMetadata() error = %v", err)
		}

		if err := verifyInstalledSourceMetadata(skillRoot, source{
			Input: "github:org/repo//skills/other@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}); err == nil || !strings.Contains(err.Error(), "mismatch with lock source") {
			t.Fatalf("expected source mismatch error, got %v", err)
		}

		if err := os.WriteFile(filepath.Join(skillRoot, "README.md"), []byte("changed"), 0o644); err != nil {
			t.Fatalf("mutate README: %v", err)
		}
		if err := verifyInstalledSourceMetadata(skillRoot, source{
			Input: "github:org/repo//skills/verify-meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("expected hash mismatch error, got %v", err)
		}

		if runtime.GOOS != "windows" {
			lockedDir := createSkillSourceForInstallTest(t, "locked-skill")
			_, hash, err := buildFileDigestsFiltered(lockedDir, map[string]struct{}{
				sourceMetadataFile: {},
			})
			if err != nil {
				t.Fatalf("buildFileDigestsFiltered() error = %v", err)
			}
			if err := writeSourceMetadata(lockedDir, sourceMetadata{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/locked-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: hash,
			}); err != nil {
				t.Fatalf("writeSourceMetadata() error = %v", err)
			}
			blocked := filepath.Join(lockedDir, "blocked.bin")
			if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
				t.Fatalf("write blocked file: %v", err)
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatalf("chmod blocked file: %v", err)
			}
			defer os.Chmod(blocked, 0o644)
			if err := verifyInstalledSourceMetadata(lockedDir, source{
				Input: "github:org/repo//skills/locked-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			}); err == nil {
				t.Fatal("expected digest read error")
			}
		}

		badMetaDir := createSkillSourceForInstallTest(t, "verify-read-error")
		if err := os.Mkdir(filepath.Join(badMetaDir, sourceMetadataFile), 0o755); err != nil {
			t.Fatalf("mkdir metadata dir: %v", err)
		}
		if err := verifyInstalledSourceMetadata(badMetaDir, source{
			Input: "github:org/repo//skills/verify-read-error@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}); err == nil {
			t.Fatal("expected metadata read error")
		}
	})

	t.Run("resolve source metadata fallback and errors", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "resolve-fallback")
		resolved, err := resolveSourceForInstall(skillRoot, skillRoot, "local-dir")
		if err != nil {
			t.Fatalf("resolveSourceForInstall() error = %v", err)
		}
		if resolved.Kind != "local-dir" {
			t.Fatalf("resolved kind = %q", resolved.Kind)
		}

		if err := os.Mkdir(filepath.Join(skillRoot, sourceMetadataFile), 0o755); err != nil {
			t.Fatalf("mkdir metadata dir: %v", err)
		}
		if resolved, err := resolveSourceForInstall(skillRoot, skillRoot, "local-dir"); err != nil {
			t.Fatalf("local resolve should ignore metadata, got err=%v", err)
		} else if resolved.Kind != "local-dir" || resolved.Input != skillRoot {
			t.Fatalf("unexpected local resolve result: %+v", resolved)
		}

		if runtime.GOOS != "windows" {
			digestErrRoot := createSkillSourceForInstallTest(t, "resolve-digest-error")
			_, hash, err := buildFileDigestsFiltered(digestErrRoot, map[string]struct{}{
				sourceMetadataFile: {},
			})
			if err != nil {
				t.Fatalf("buildFileDigestsFiltered() error = %v", err)
			}
			if err := writeSourceMetadata(digestErrRoot, sourceMetadata{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/resolve-digest-error@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: hash,
			}); err != nil {
				t.Fatalf("writeSourceMetadata() error = %v", err)
			}
			blocked := filepath.Join(digestErrRoot, "blocked.bin")
			if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
				t.Fatalf("write blocked file: %v", err)
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatalf("chmod blocked file: %v", err)
			}
			defer os.Chmod(blocked, 0o644)
			if _, err := resolveSourceForInstall(digestErrRoot, "github:org/repo//skills/resolve-digest-error@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source"); err == nil {
				t.Fatal("expected digest error while resolving source metadata")
			}
		}
	})
}
