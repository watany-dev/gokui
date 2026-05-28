package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestEvaluateUpdateSkillLockValidationBranches(t *testing.T) {
	t.Run("empty lock source input is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "empty-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "   ",
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
			Name: "empty-source-input",
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
		if !strings.Contains(got.Message, "lock source input is empty") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with control characters is lockfile invalid", func(t *testing.T) {
		sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: sourceInput + "\npayload",
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
			Name: "control-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with unicode obfuscation characters is lockfile invalid", func(t *testing.T) {
		sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unicode-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: sourceInput + "\u200dpayload",
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
			Name: "unicode-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with edge C1 control character is lockfile invalid", func(t *testing.T) {
		sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "edge-control-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "\u0085" + sourceInput,
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
			Name: "edge-control-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with C1-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "c1-only-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "\u0085",
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
			Name: "c1-only-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with C0 NUL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "nul-only-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "\u0000",
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
			Name: "nul-only-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with DEL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-only-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "\u007f",
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
			Name: "del-only-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source input with DEL-edge control character is lockfile invalid", func(t *testing.T) {
		sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-edge-source-input",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "\u007f" + sourceInput,
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
			Name: "del-edge-source-input",
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
		if !strings.Contains(got.Message, "lock source input must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("empty lock source kind is lockfile invalid", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		src := createSkillSourceForInstallTest(t, "fallback-kind-skill")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "fallback-kind-skill", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}
		lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
		if err != nil {
			t.Fatalf("readInstallLock() error = %v", err)
		}
		lock.Source.Kind = ""

		item := updateSkillItem{
			Name: "fallback-kind-skill",
			Path: installedPath,
			Source: source{
				Input: lock.Source.Input,
				Kind:  "",
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
		if !strings.Contains(got.Message, "lock source kind is empty") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with C0/C1 control characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "control-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local\u008fdir",
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
			Name: "control-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with unicode obfuscation characters is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "unicode-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "local-dir\u200d",
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
			Name: "unicode-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with edge C1 control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "edge-control-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "\u0085local-dir",
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
			Name: "edge-control-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with C1-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "c1-only-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "\u0085",
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
			Name: "c1-only-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with C0 NUL-only control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "nul-only-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "\u0000",
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
			Name: "nul-only-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with DEL control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "\u007f",
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
			Name: "del-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})

	t.Run("lock source kind with DEL edge control character is lockfile invalid", func(t *testing.T) {
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "del-edge-source-kind",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: t.TempDir(),
				Kind:  "\u007flocal-dir",
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
			Name: "del-edge-source-kind",
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
		if !strings.Contains(got.Message, "lock source kind must not contain C0/C1 control characters") {
			t.Fatalf("message = %q", got.Message)
		}
	})
}
