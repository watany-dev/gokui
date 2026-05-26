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

	t.Run("resolveSourceForInstall returns metadata read errors for github source", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, sourceMetadataFile), []byte("{"), 0o644); err != nil {
			t.Fatalf("write invalid metadata: %v", err)
		}
		_, err := resolveSourceForInstall(dir, "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "github-source")
		if err == nil || !strings.Contains(err.Error(), "invalid source metadata JSON") {
			t.Fatalf("expected metadata read error, got %v", err)
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
		if _, _, err := readSourceMetadata(dirAsMeta); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSpecialFile) {
			t.Fatalf("expected read error, got %v", err)
		}
		if err := writeSourceMetadata(dirAsMeta, sourceMetadata{Schema: sourceMetadataSchemaVersion}); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSpecialFile) {
			t.Fatalf("expected metadata write special-file rejection, got %v", err)
		}

		if runtime.GOOS != "windows" {
			dirWithSymlink := t.TempDir()
			target := filepath.Join(dirWithSymlink, "real-source.json")
			if err := os.WriteFile(target, []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
				t.Fatalf("write real metadata file: %v", err)
			}
			if err := os.Symlink("real-source.json", filepath.Join(dirWithSymlink, sourceMetadataFile)); err != nil {
				t.Fatalf("create metadata symlink: %v", err)
			}
			if _, _, err := readSourceMetadata(dirWithSymlink); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSymlink) {
				t.Fatalf("expected source metadata symlink rejection, got %v", err)
			}

			base := t.TempDir()
			realParent := filepath.Join(base, "real-parent")
			if err := os.Mkdir(realParent, 0o755); err != nil {
				t.Fatalf("mkdir real parent: %v", err)
			}
			realSkill := filepath.Join(realParent, "skill")
			if err := os.Mkdir(realSkill, 0o755); err != nil {
				t.Fatalf("mkdir real skill: %v", err)
			}
			validMeta := []byte(`{
  "schema": "gokui.source/v1",
  "source_input": "github:org/repo//skills/skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
  "source_kind": "github-source",
  "resolved_ref": "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
  "fetched_at": "2026-05-23T00:00:00Z",
  "skill_root_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}`)
			if err := os.WriteFile(filepath.Join(realSkill, sourceMetadataFile), validMeta, 0o644); err != nil {
				t.Fatalf("write valid metadata: %v", err)
			}
			linkParent := filepath.Join(base, "link-parent")
			if err := os.Symlink("real-parent", linkParent); err != nil {
				t.Fatalf("create parent symlink: %v", err)
			}
			if _, _, err := readSourceMetadata(filepath.Join(linkParent, "skill")); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSymlink) {
				t.Fatalf("expected ancestor source metadata symlink rejection, got %v", err)
			}

			writeSymlinkDir := t.TempDir()
			writeTarget := filepath.Join(writeSymlinkDir, "real-target.json")
			if err := os.WriteFile(writeTarget, []byte("original"), 0o644); err != nil {
				t.Fatalf("write metadata write target: %v", err)
			}
			if err := os.Symlink("real-target.json", filepath.Join(writeSymlinkDir, sourceMetadataFile)); err != nil {
				t.Fatalf("create write-path metadata symlink: %v", err)
			}
			if err := writeSourceMetadata(writeSymlinkDir, sourceMetadata{Schema: sourceMetadataSchemaVersion}); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSymlink) {
				t.Fatalf("expected metadata write symlink rejection, got %v", err)
			}
			targetAfterWrite, err := os.ReadFile(writeTarget)
			if err != nil {
				t.Fatalf("read metadata write target after rejection: %v", err)
			}
			if string(targetAfterWrite) != "original" {
				t.Fatalf("metadata write should not follow symlink target, got %q", string(targetAfterWrite))
			}

			writeAncestorBase := t.TempDir()
			writeRealParent := filepath.Join(writeAncestorBase, "real-parent")
			if err := os.Mkdir(writeRealParent, 0o755); err != nil {
				t.Fatalf("mkdir write real parent: %v", err)
			}
			writeRealSkill := filepath.Join(writeRealParent, "skill")
			if err := os.Mkdir(writeRealSkill, 0o755); err != nil {
				t.Fatalf("mkdir write real skill: %v", err)
			}
			writeLinkParent := filepath.Join(writeAncestorBase, "link-parent")
			if err := os.Symlink("real-parent", writeLinkParent); err != nil {
				t.Fatalf("create write parent symlink: %v", err)
			}
			if err := writeSourceMetadata(filepath.Join(writeLinkParent, "skill"), sourceMetadata{Schema: sourceMetadataSchemaVersion}); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSymlink) {
				t.Fatalf("expected ancestor metadata write symlink rejection, got %v", err)
			}
		}

		dirWithInvalidFields := t.TempDir()
		if err := os.WriteFile(filepath.Join(dirWithInvalidFields, sourceMetadataFile), []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
			t.Fatalf("write invalid-field metadata: %v", err)
		}
		if _, _, err := readSourceMetadata(dirWithInvalidFields); err == nil {
			t.Fatal("expected metadata validation error")
		}

		dirWithInvalidUTF8 := t.TempDir()
		invalidUTF8Metadata := []byte("{\"schema\":\"gokui.source/v1\",\"source_input\":\"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\",\"source_kind\":\"github-source\",\"resolved_ref\":\"8f3c2d1a4b5c6d7e8f901234567890abcdef1234\",\"fetched_at\":\"2026-05-23T00:00:00Z\",\"skill_root_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"note\":\"")
		invalidUTF8Metadata = append(invalidUTF8Metadata, 0xff)
		invalidUTF8Metadata = append(invalidUTF8Metadata, []byte("\"}")...)
		if err := os.WriteFile(filepath.Join(dirWithInvalidUTF8, sourceMetadataFile), invalidUTF8Metadata, 0o644); err != nil {
			t.Fatalf("write invalid-utf8 metadata: %v", err)
		}
		if _, _, err := readSourceMetadata(dirWithInvalidUTF8); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataInvalidUTF8) {
			t.Fatalf("expected invalid utf-8 metadata error, got %v", err)
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

		if runtime.GOOS != "windows" {
			unreadableDir := t.TempDir()
			unreadablePath := filepath.Join(unreadableDir, sourceMetadataFile)
			if err := os.WriteFile(unreadablePath, []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
				t.Fatalf("write unreadable metadata file: %v", err)
			}
			if err := os.Chmod(unreadablePath, 0o000); err != nil {
				t.Fatalf("chmod unreadable metadata file: %v", err)
			}
			defer os.Chmod(unreadablePath, 0o644)
			if _, _, err := readSourceMetadata(unreadableDir); err == nil || !strings.Contains(err.Error(), "failed to read source metadata") {
				t.Fatalf("expected unreadable metadata read error, got %v", err)
			}

			readOnlyDir := t.TempDir()
			if err := os.Chmod(readOnlyDir, 0o555); err != nil {
				t.Fatalf("chmod readonly dir: %v", err)
			}
			defer os.Chmod(readOnlyDir, 0o755)
			err := writeSourceMetadata(readOnlyDir, sourceMetadata{Schema: sourceMetadataSchemaVersion})
			if err == nil || !strings.Contains(err.Error(), "failed to write source metadata") {
				t.Fatalf("expected readonly metadata write error, got %v", err)
			}
		}
	})

	t.Run("ensureSourceMetadataStableFile detects source replacement", func(t *testing.T) {
		root := t.TempDir()
		firstPath := filepath.Join(root, "first.json")
		if err := os.WriteFile(firstPath, []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
			t.Fatalf("write first metadata: %v", err)
		}
		secondPath := filepath.Join(root, "second.json")
		if err := os.WriteFile(secondPath, []byte(`{"schema":"gokui.source/v1"}`), 0o644); err != nil {
			t.Fatalf("write second metadata: %v", err)
		}

		firstInfo, err := os.Lstat(firstPath)
		if err != nil {
			t.Fatalf("lstat first metadata: %v", err)
		}
		secondInfo, err := os.Lstat(secondPath)
		if err != nil {
			t.Fatalf("lstat second metadata: %v", err)
		}

		if err := ensureSourceMetadataStableFile(firstInfo, firstInfo, firstPath); err != nil {
			t.Fatalf("same file should pass, got %v", err)
		}
		err = ensureSourceMetadataStableFile(firstInfo, secondInfo, secondPath)
		if err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSourceChanged) {
			t.Fatalf("expected changed-source error, got %v", err)
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
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/./x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo// skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills//x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/repo.git//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:Owner/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/Repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/.repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/repo.//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:owner/re..po//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@shadow@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills:x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/con@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/COM¹.txt@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/\u202edemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/\u200bdemo@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/my skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u00a01234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u200b1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\u202e1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\U000E00011234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\ufe0f1234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:or\u00a0g/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/re\u200bpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:or\U000E0001g/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/re\ufe0fpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/ x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x.@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:      "gokui.source/v1",
				SourceInput: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:  "github-source",
				ResolvedRef: "abcdef0",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     " github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234 ",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			{
				Schema:          "gokui.source/v1",
				SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				SourceKind:      "github-source",
				ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				FetchedAt:       "2026-05-23T00:00:00Z",
				SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
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

	t.Run("validate metadata rejects non-utf8 source input", func(t *testing.T) {
		sourceInput := "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		invalidSourceInput := string(append([]byte(sourceInput), 0xff))
		err := validateSourceMetadata(sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     invalidSourceInput,
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		})
		if err == nil {
			t.Fatal("expected invalid source_input utf-8 error")
		}
		if !strings.Contains(err.Error(), "source metadata has invalid github source input") {
			t.Fatalf("expected metadata source_input context, got %v", err)
		}
		if !strings.Contains(err.Error(), "github source must be valid UTF-8") {
			t.Fatalf("expected utf-8 validation detail, got %v", err)
		}
	})

	t.Run("validate metadata rejects C0/C1 controls with explicit errors", func(t *testing.T) {
		valid := sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}
		cases := []struct {
			name       string
			mutate     func(*sourceMetadata)
			detailPart string
		}{
			{
				name: "schema has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.Schema = "gokui.source/v1\u008f"
				},
				detailPart: "schema must not contain C0/C1 control characters",
			},
			{
				name: "source_input has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SourceInput = "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef12\u008f4"
				},
				detailPart: "source_input must not contain C0/C1 control characters",
			},
			{
				name: "source_kind has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "github-source\u008f"
				},
				detailPart: "source_kind must not contain C0/C1 control characters",
			},
			{
				name: "source_kind is empty",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = ""
				},
				detailPart: "source_kind is empty",
			},
			{
				name: "source_kind has surrounding whitespace",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = " github-source "
				},
				detailPart: "source_kind must not contain leading or trailing whitespace",
			},
			{
				name: "source_kind must be canonical lowercase",
				mutate: func(m *sourceMetadata) {
					m.SourceKind = "GitHub-Source"
				},
				detailPart: "source_kind must be canonical lowercase",
			},
			{
				name: "resolved_ref has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.ResolvedRef = "8f3c2d1a4b5c6d7e8f901234567890abcdef12\u008f4"
				},
				detailPart: "resolved_ref must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = "2026-05-23T00:00:00\u008fZ"
				},
				detailPart: "fetched_at must not contain C0/C1 control characters",
			},
			{
				name: "fetched_at has surrounding whitespace",
				mutate: func(m *sourceMetadata) {
					m.FetchedAt = " 2026-05-23T00:00:00Z "
				},
				detailPart: "fetched_at must not contain leading or trailing whitespace",
			},
			{
				name: "skill_root_sha256 has C0/C1 control",
				mutate: func(m *sourceMetadata) {
					m.SkillRootSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\u008f"
				},
				detailPart: "skill_root_sha256 must not contain C0/C1 control characters",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mut := valid
				tc.mutate(&mut)
				err := validateSourceMetadata(mut)
				if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
					t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
				}
			})
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
