package app

import (
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestEvaluateUpdateSkillLockFileValidationBranches(t *testing.T) {
	t.Run("non-canonical lock root hash is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "bad-root-hash",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("A", 64),
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
			Name: "bad-root-hash",
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
		if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !strings.Contains(got.Message, "root_sha256 must be a canonical lowercase 64-char hex digest") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("empty lock file snapshot is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "empty-lock-files",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files:      nil,
			},
			Policy: lockPolicy{
				Profile:  policyProfileStrict,
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "empty-lock-files",
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
		if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !strings.Contains(got.Message, "lock skill files is empty") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("duplicate lock file path is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "duplicate-lock-file",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
					{Path: "SKILL.md", SHA256: strings.Repeat("c", 64), Bytes: 2},
				},
			},
			Policy: lockPolicy{
				Profile:  policyProfileStrict,
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "duplicate-lock-file",
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
		if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !strings.Contains(got.Message, "duplicate lock file path: SKILL.md") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("negative lock file bytes is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "negative-lock-bytes",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: -1},
				},
			},
			Policy: lockPolicy{
				Profile:  policyProfileStrict,
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "negative-lock-bytes",
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
		if got.Status != "ERROR" || got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("unexpected result: %+v", got)
		}
		if !strings.Contains(got.Message, "lock file bytes is negative: SKILL.md") {
			t.Fatalf("message = %q", got.Message)
		}
	})
}
