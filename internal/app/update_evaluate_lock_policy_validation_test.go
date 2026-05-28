package app

import (
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestEvaluateUpdateSkillLockPolicyValidationBranches(t *testing.T) {
	t.Run("lock policy profile with C0/C1 control characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-profile",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "stric\u008ft",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-profile",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy profile with C1-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "c1-only-policy-profile",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "\u0085",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "c1-only-policy-profile",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy profile with C0 NUL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "nul-only-policy-profile",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "\u0000",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "nul-only-policy-profile",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy profile with DEL control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-profile-del",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "\u007f",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-profile-del",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy profile with DEL edge control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-profile-del-edge",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "\u007fstrict",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-profile-del-edge",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy profile with unicode obfuscation characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unicode-policy-profile",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict\u200d",
				Decision: "pass",
			},
		}
		item := updateSkillItem{
			Name: "unicode-policy-profile",
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
		if !strings.Contains(got.Message, "lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with C0/C1 control characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-decision",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pas\u008fs",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-decision",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with edge C0/C1 control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-decision-edge",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "\u0085pass",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-decision-edge",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with C1-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "c1-only-policy-decision",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "\u0085",
			},
		}
		item := updateSkillItem{
			Name: "c1-only-policy-decision",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with C0 NUL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "nul-only-policy-decision",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "\u0000",
			},
		}
		item := updateSkillItem{
			Name: "nul-only-policy-decision",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with DEL control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-decision-del",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "\u007f",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-decision-del",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with DEL edge control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-policy-decision-del-edge",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "\u007fpass",
			},
		}
		item := updateSkillItem{
			Name: "control-policy-decision-del-edge",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with unicode obfuscation characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unicode-policy-decision",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass\u200d",
			},
		}
		item := updateSkillItem{
			Name: "unicode-policy-decision",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock policy decision with surrounding whitespace is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "whitespace-policy-decision",
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
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: " pass ",
			},
		}
		item := updateSkillItem{
			Name: "whitespace-policy-decision",
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
		if !strings.Contains(got.Message, "lock policy decision must not contain leading or trailing whitespace") {
			t.Fatalf("message = %q", got.Message)
		}
	})
}
