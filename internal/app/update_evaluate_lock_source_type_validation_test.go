package app

import (
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestEvaluateUpdateSkillLockSourceTypeValidationBranches(t *testing.T) {
	t.Run("empty lock source type is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "empty-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "",
				Input: t.TempDir(),
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
			Name: "empty-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type is empty") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with C0/C1 control characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "loca\u008fl",
				Input: t.TempDir(),
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
			Name: "control-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with unicode obfuscation characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unicode-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local\u200d",
				Input: t.TempDir(),
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
			Name: "unicode-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with edge C1 control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "edge-control-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "\u0085local",
				Input: t.TempDir(),
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
			Name: "edge-control-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with C1-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "c1-only-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "\u0085",
				Input: t.TempDir(),
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
			Name: "c1-only-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with C0 NUL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "nul-only-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "\u0000",
				Input: t.TempDir(),
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
			Name: "nul-only-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with DEL control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "\u007f",
				Input: t.TempDir(),
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
			Name: "del-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source type with DEL edge control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-edge-source-type",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "\u007flocal",
				Input: t.TempDir(),
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
			Name: "del-edge-source-type",
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
		if got.Status != "ERROR" {
			t.Fatalf("status = %q, want ERROR", got.Status)
		}
		if got.ErrorCode != updateCodeLockfileInvalid {
			t.Fatalf("error_code = %q, want %q", got.ErrorCode, updateCodeLockfileInvalid)
		}
		if !strings.Contains(got.Message, "lock source type must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})
}
