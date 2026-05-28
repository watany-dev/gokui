package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"testing/quick"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestSetDiffProperties(t *testing.T) {
	prop := func(current []string, previous []string) bool {
		got := setDiff(current, previous)
		if !sort.StringsAreSorted(got) {
			return false
		}

		previousSet := make(map[string]struct{}, len(previous))
		for _, v := range previous {
			previousSet[v] = struct{}{}
		}
		currentSet := make(map[string]struct{}, len(current))
		for _, v := range current {
			currentSet[v] = struct{}{}
		}

		for _, v := range got {
			if _, exists := currentSet[v]; !exists {
				return false
			}
			if _, excluded := previousSet[v]; excluded {
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("setDiff property failed: %v", err)
	}
}

func TestEvaluateUpdateSkillAdditionalBranches(t *testing.T) {
	t.Run("returns error when installed path cannot be scanned for urls", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "url-error-skill")
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "url-error-skill",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: src,
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
			Policy: lockPolicy{
				Profile:  policyProfileStrict,
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "url-error-skill",
			Path: filepath.Join(t.TempDir(), "missing-installed-path"),
			Source: source{
				Input: src,
				Kind:  "local-dir",
			},
			Diff: updateDiff{
				Added:   []string{},
				Removed: []string{},
				Changed: []string{},
			},
		}
		got, err := evaluateUpdateSkill(item, lock, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("evaluateUpdateSkill() error = %v", err)
		}
		if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !strings.Contains(got.Message, "failed to evaluate install report for update baseline") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("source preparation failure returns ERROR status", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "missing-source-skill",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Join(t.TempDir(), "missing-source"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  policyProfileStrict,
				Decision: "pass",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		item := updateSkillItem{
			Name: "missing-source-skill",
			Path: t.TempDir(),
			Source: source{
				Input: lock.Source.Input,
				Kind:  lock.Source.Kind,
			},
			Diff: updateDiff{
				Added:   []string{},
				Removed: []string{},
				Changed: []string{},
			},
		}
		got, err := evaluateUpdateSkill(item, lock, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("evaluateUpdateSkill() error = %v", err)
		}
		if got.Status != "ERROR" || got.ErrorCode != updateCodeSourcePrepareError {
			t.Fatalf("unexpected result for source prepare failure: %+v", got)
		}
		if !strings.Contains(got.Message, "source not found") {
			t.Fatalf("unexpected source prepare message: %+v", got)
		}
	})

	t.Run("github pinned source prepare error returns ERROR status", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		src := createSkillSourceForInstallTest(t, "github-prepare-error-skill")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "github-prepare-error-skill", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}

		_, installedRootHash, err := buildFileDigestsFiltered(installedPath, map[string]struct{}{
			sourceMetadataFile: {},
			installReportFile:  {},
			installLockFile:    {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		if err := writeSourceMetadata(installedPath, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/github-prepare-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: installedRootHash,
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
		if err != nil {
			t.Fatalf("readInstallLock() error = %v", err)
		}
		lock.Source = lockSource{
			Type:  "github",
			Input: "github:org/repo//skills/github-prepare-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}
		reportPath := filepath.Join(installedPath, installReportFile)
		reportRaw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read install report: %v", err)
		}
		var installedReport installReport
		if err := json.Unmarshal(reportRaw, &installedReport); err != nil {
			t.Fatalf("unmarshal install report: %v", err)
		}
		installedReport.Source = source{
			Input: "github:org/repo//skills/github-prepare-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}
		updatedReport, err := json.MarshalIndent(installedReport, "", "  ")
		if err != nil {
			t.Fatalf("marshal install report: %v", err)
		}
		if err := os.WriteFile(reportPath, updatedReport, 0o644); err != nil {
			t.Fatalf("write updated install report: %v", err)
		}

		cleanupCalled := false

		item := updateSkillItem{
			Name: "github-prepare-error-skill",
			Path: installedPath,
			Source: source{
				Input: lock.Source.Input,
				Kind:  "github-source",
			},
			Diff: updateDiff{
				Added:   []string{},
				Removed: []string{},
				Changed: []string{},
			},
		}
		got, err := evaluateUpdateSkillWithDeps(item, lock, false, policypkg.Config{}, updateDeps{
			PrepareEvaluationSource: func(input string, sourceKind string) (string, func(), error) {
				return "", func() { cleanupCalled = true }, errors.New("fetch failed")
			},
		})
		if err != nil {
			t.Fatalf("evaluateUpdateSkill() unexpected error = %v", err)
		}
		if got.Status != "ERROR" {
			t.Fatalf("expected ERROR status, got %+v", got)
		}
		if !cleanupCalled {
			t.Fatal("cleanup callback should be called")
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("returns error when scan fails on unreadable markdown", func(t *testing.T) {
			targetRoot := filepath.Join(t.TempDir(), "skills")
			if err := os.MkdirAll(targetRoot, 0o755); err != nil {
				t.Fatalf("mkdir target root: %v", err)
			}
			src := createSkillSourceForInstallTest(t, "scan-fail-update-skill")
			report := installReport{
				SchemaVersion: "0.1.0-draft",
				Source:        source{Input: src, Kind: "local-dir"},
				PolicyProfile: "strict",
				Decision:      "PASS",
			}
			installedPath, _, err := installSkillAtomic(src, targetRoot, "scan-fail-update-skill", report)
			if err != nil {
				t.Fatalf("installSkillAtomic() error = %v", err)
			}
			lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
			if err != nil {
				t.Fatalf("readInstallLock() error = %v", err)
			}

			refDir := filepath.Join(src, "references")
			if err := os.Mkdir(refDir, 0o755); err != nil {
				t.Fatalf("mkdir references: %v", err)
			}
			blocked := filepath.Join(refDir, "blocked.md")
			if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
				t.Fatalf("write blocked file: %v", err)
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatalf("chmod blocked file: %v", err)
			}
			defer os.Chmod(blocked, 0o644)

			item := updateSkillItem{
				Name: "scan-fail-update-skill",
				Path: installedPath,
				Source: source{
					Input: src,
					Kind:  "local-dir",
				},
				Diff: updateDiff{
					Added:   []string{},
					Removed: []string{},
					Changed: []string{},
				},
			}
			_, err = evaluateUpdateSkill(item, lock, false, policypkg.Config{})
			if err == nil {
				t.Fatal("expected scan failure error")
			}
		})

		t.Run("returns error when digesting source files fails", func(t *testing.T) {
			targetRoot := filepath.Join(t.TempDir(), "skills")
			if err := os.MkdirAll(targetRoot, 0o755); err != nil {
				t.Fatalf("mkdir target root: %v", err)
			}
			src := createSkillSourceForInstallTest(t, "digest-fail-update-skill")
			report := installReport{
				SchemaVersion: "0.1.0-draft",
				Source:        source{Input: src, Kind: "local-dir"},
				PolicyProfile: "strict",
				Decision:      "PASS",
			}
			installedPath, _, err := installSkillAtomic(src, targetRoot, "digest-fail-update-skill", report)
			if err != nil {
				t.Fatalf("installSkillAtomic() error = %v", err)
			}
			lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
			if err != nil {
				t.Fatalf("readInstallLock() error = %v", err)
			}

			blocked := filepath.Join(src, "blocked.bin")
			if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
				t.Fatalf("write blocked bin: %v", err)
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatalf("chmod blocked bin: %v", err)
			}
			defer os.Chmod(blocked, 0o644)

			item := updateSkillItem{
				Name: "digest-fail-update-skill",
				Path: installedPath,
				Source: source{
					Input: src,
					Kind:  "local-dir",
				},
				Diff: updateDiff{
					Added:   []string{},
					Removed: []string{},
					Changed: []string{},
				},
			}
			_, err = evaluateUpdateSkill(item, lock, false, policypkg.Config{})
			if err == nil {
				t.Fatal("expected digest failure error")
			}
		})
	}
}
