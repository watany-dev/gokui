package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestInstallUsesAndValidatesSourceMetadata(t *testing.T) {
	t.Run("github install writes source metadata and verifies cleanly", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "github-install-meta")
		origFetch := fetchGitHubSkill
		t.Cleanup(func() { fetchGitHubSkill = origFetch })
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return src, nil, nil
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		var stdout strings.Builder
		var stderr strings.Builder
		input := "github:org/repo//skills/github-install-meta@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		code := runInstall([]string{input, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runInstall() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}

		installedPath := filepath.Join(targetRoot, "github-install-meta")
		if _, err := os.Stat(filepath.Join(installedPath, sourceMetadataFile)); err != nil {
			t.Fatalf("expected installed source metadata file: %v", err)
		}

		verifyReport, err := verifyLock(installedPath)
		if err != nil {
			t.Fatalf("verifyLock() error = %v", err)
		}
		if verifyReport.Status != "VERIFIED" {
			t.Fatalf("verify status = %q, want VERIFIED", verifyReport.Status)
		}
		assertCheckOK(t, verifyReport.Checks, "source_metadata")
	})

	t.Run("local install does not trust embedded source metadata", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "meta-skill")
		_, rootHash, err := buildFileDigestsFiltered(src, map[string]struct{}{
			sourceMetadataFile: {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		if err := writeSourceMetadata(src, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: rootHash,
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		var stdout strings.Builder
		var stderr strings.Builder
		code := runInstall([]string{src, "--target", "custom:" + targetRoot, "--profile", "strict"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("runInstall() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty, got %q", stderr.String())
		}

		lockRaw, err := os.ReadFile(filepath.Join(targetRoot, "meta-skill", installLockFile))
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(lockRaw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		if lock.Source.Kind != "local-dir" {
			t.Fatalf("lock source kind = %q, want local-dir", lock.Source.Kind)
		}
		if lock.Source.Input != src {
			t.Fatalf("lock source input = %q", lock.Source.Input)
		}
	})

	t.Run("github install rejects mismatched source metadata hash", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "bad-meta-skill")
		if err := writeSourceMetadata(src, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/bad-meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: strings.Repeat("0", 64),
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		origFetch := fetchGitHubSkill
		t.Cleanup(func() { fetchGitHubSkill = origFetch })
		fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
			return src, nil, nil
		}

		var stdout strings.Builder
		var stderr strings.Builder
		code := runInstall([]string{"github:org/repo//skills/bad-meta-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--target", "custom:" + filepath.Join(t.TempDir(), "skills"), "--profile", "strict"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runInstall() code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "source metadata hash mismatch") {
			t.Fatalf("stderr should include source metadata hash mismatch, got %q", stderr.String())
		}
	})
}

func TestWriteInstallMetadataGitHubSource(t *testing.T) {
	t.Run("writes source metadata for github source", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "write-meta-github")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "github:org/repo//skills/write-meta-github@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			Installed:     true,
			InstalledPath: skillRoot,
		}

		if err := writeInstallMetadata(skillRoot, report); err != nil {
			t.Fatalf("writeInstallMetadata() error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(skillRoot, sourceMetadataFile)); err != nil {
			t.Fatalf("expected source metadata file: %v", err)
		}

		lock, err := readInstallLock(filepath.Join(skillRoot, installLockFile))
		if err != nil {
			t.Fatalf("readInstallLock() error = %v", err)
		}
		if lock.Source.Kind != "github-source" {
			t.Fatalf("lock source kind = %q, want github-source", lock.Source.Kind)
		}
	})

	t.Run("rejects invalid github source metadata input", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "write-meta-invalid")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "github:org/repo/skills/write-meta-invalid@main",
				Kind:  "github-source",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			Installed:     true,
			InstalledPath: skillRoot,
		}
		if err := writeInstallMetadata(skillRoot, report); err == nil || !strings.Contains(err.Error(), "invalid github source") {
			t.Fatalf("expected invalid github source error, got %v", err)
		}
	})

	t.Run("rejects non-pinned github ref", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "write-meta-unpinned")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "github:org/repo//skills/write-meta-unpinned@main",
				Kind:  "github-source",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			Installed:     true,
			InstalledPath: skillRoot,
		}
		if err := writeInstallMetadata(skillRoot, report); err == nil || !strings.Contains(err.Error(), "commit-pinned") {
			t.Fatalf("expected commit-pinned error, got %v", err)
		}
	})

	t.Run("returns error when source metadata path is not writable file path", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "write-meta-path-error")
		if err := os.Mkdir(filepath.Join(skillRoot, sourceMetadataFile), 0o755); err != nil {
			t.Fatalf("mkdir metadata collision path: %v", err)
		}
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "github:org/repo//skills/write-meta-path-error@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			Installed:     true,
			InstalledPath: skillRoot,
		}
		if err := writeInstallMetadata(skillRoot, report); err == nil || !strings.Contains(err.Error(), ruleSourceMetadataSpecialFile) {
			t.Fatalf("expected source metadata write error, got %v", err)
		}
	})

	t.Run("returns error when github source digest build fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		skillRoot := createSkillSourceForInstallTest(t, "write-meta-digest-error")
		blocked := filepath.Join(skillRoot, "blocked.md")
		if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "github:org/repo//skills/write-meta-digest-error@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
				Kind:  "github-source",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			Installed:     true,
			InstalledPath: skillRoot,
		}
		if err := writeInstallMetadata(skillRoot, report); err == nil {
			t.Fatal("expected digest build error for unreadable file")
		}
	})
}
