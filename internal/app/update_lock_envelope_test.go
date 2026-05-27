package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateUpdateLockEnvelope(t *testing.T) {
	valid := installLock{
		Schema:      "gokui.lock/v1",
		Name:        "update-lock",
		InstalledAt: "2026-05-24T00:00:00Z",
		Source: lockSource{
			Type:  "local",
			Input: filepath.Clean("/tmp/update-lock"),
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
			SeverityOverrides: []severityOverrideAudit{
				{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "approved for controlled fixture",
					ApprovedBy:        "security-reviewer",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
			},
		},
		Skill: lockSkill{
			RootSHA256: strings.Repeat("a", 64),
			Files: []lockFileHash{
				{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
			},
		},
	}
	if err := validateUpdateLockEnvelope(valid, "update-lock"); err != nil {
		t.Fatalf("validateUpdateLockEnvelope(valid) error = %v", err)
	}

	cases := []struct {
		name       string
		mutate     func(*installLock)
		detailPart string
	}{
		{
			name: "unsupported schema",
			mutate: func(l *installLock) {
				l.Schema = "gokui.lock/v0"
			},
			detailPart: "unsupported lock schema",
		},
		{
			name: "schema has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Schema = "gokui.lock/v1\u008f"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Schema = "\u0085gokui.lock/v1"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C1-only control character",
			mutate: func(l *installLock) {
				l.Schema = "\u0085"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Schema = "\u0000"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character only",
			mutate: func(l *installLock) {
				l.Schema = "\u007f"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Schema = "\u007fgokui.lock/v1"
			},
			detailPart: "lock schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Schema = " gokui.lock/v1 "
			},
			detailPart: "lock schema must not contain leading or trailing whitespace",
		},
		{
			name: "schema has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Schema = "gokui.lock/v1\u200d"
			},
			detailPart: "lock schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty name",
			mutate: func(l *installLock) {
				l.Name = ""
			},
			detailPart: "lock name is empty",
		},
		{
			name: "name mismatch",
			mutate: func(l *installLock) {
				l.Name = "other"
			},
			detailPart: "lock name does not match installed skill directory",
		},
		{
			name: "name has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Name = "update-lock\u008f"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u0085update-lock"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0085"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0000"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u007f"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u007fupdate-lock"
			},
			detailPart: "lock name must not contain C0/C1 control characters",
		},
		{
			name: "name has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Name = "update-lock\u200d"
			},
			detailPart: "lock name must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "installed_at has C0/C1 control character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-24T00:00:00\u008fZ"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u00852026-05-24T00:00:00Z"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0085"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0000"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f2026-05-24T00:00:00Z"
			},
			detailPart: "lock installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-24T00:00:00Z\u200d"
			},
			detailPart: "lock installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "invalid installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = "not-rfc3339"
			},
			detailPart: "lock installed_at must be RFC3339",
		},
		{
			name: "invalid severity override entry",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].RuleID = ""
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override rule_id has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].RuleID = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "duplicate severity override rule_id",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides = []severityOverrideAudit{
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "first",
						ApprovedBy:        "security-reviewer",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "low",
						Justification:     "second",
						ApprovedBy:        "security-reviewer",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T01:00:00Z",
					},
				}
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override approved_by has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].ApprovedBy = " reviewer "
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override approved_by has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].ApprovedBy = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override previous_severity has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].PreviousSeverity = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override effective_severity has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].EffectiveSeverity = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override justification has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].Justification = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override approved_by has zero-width character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].ApprovedBy = "reviewer\u200d"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override source has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].Source = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "severity override applied_at has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].AppliedAt = "\u0000"
			},
			detailPart: "lock policy severity_overrides is invalid",
		},
		{
			name: "negative findings summary",
			mutate: func(l *installLock) {
				l.Findings.High = -1
			},
			detailPart: "lock findings summary is invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := valid
			mut.Skill.Files = append([]lockFileHash(nil), valid.Skill.Files...)
			mut.Policy.SeverityOverrides = append([]severityOverrideAudit(nil), valid.Policy.SeverityOverrides...)
			tc.mutate(&mut)
			err := validateUpdateLockEnvelope(mut, "update-lock")
			if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
				t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
			}
		})
	}
}

func TestValidateUpdateLockAgainstInstallReport(t *testing.T) {
	t.Run("missing install report is tolerated", func(t *testing.T) {
		path := t.TempDir()
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "no-report",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Clean("/tmp/no-report"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		if err := validateUpdateLockAgainstInstallReport(path, lock); err != nil {
			t.Fatalf("validateUpdateLockAgainstInstallReport() error = %v", err)
		}
	})

	t.Run("report mismatch fails lock baseline validation", func(t *testing.T) {
		skillPath := t.TempDir()
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "report-mismatch",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: "/tmp/src",
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
				SeverityOverrides: []severityOverrideAudit{
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "approved for controlled fixture",
						ApprovedBy:        "security-reviewer",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
				},
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}

		report := installReport{
			SchemaVersion: reportSchemaVersion,
			Source: source{
				Input: "/tmp/src",
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			InstalledPath: skillPath,
			Installed:     true,
			Findings:      []inspectFinding{},
		}
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write install report: %v", err)
		}

		err = validateUpdateLockAgainstInstallReport(skillPath, lock)
		if err == nil || !strings.Contains(err.Error(), "install report does not match lock baseline") {
			t.Fatalf("expected install-report baseline mismatch, got %v", err)
		}
	})

	t.Run("report stat failure is surfaced", func(t *testing.T) {
		fileAsRoot := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(fileAsRoot, []byte("x"), 0o644); err != nil {
			t.Fatalf("write fileAsRoot: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "no-report",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Clean("/tmp/no-report"),
				Kind:  "local-dir",
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
		}
		err := validateUpdateLockAgainstInstallReport(fileAsRoot, lock)
		if err == nil || !strings.Contains(err.Error(), "failed to evaluate install report for update baseline") {
			t.Fatalf("expected install-report stat failure, got %v", err)
		}
	})
}

func TestValidateUpdateLockEnvelopeAndSkillSnapshotBranches(t *testing.T) {
	valid := installLock{
		Schema:      lockSchemaVersion,
		Name:        "skill-a",
		InstalledAt: "2026-05-24T00:00:00Z",
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
		Findings: lockFindingSummary{
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
		Skill: lockSkill{
			RootSHA256: strings.Repeat("a", 64),
			Files: []lockFileHash{
				{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
			},
		},
	}

	t.Run("envelope success with explicit and empty expected name", func(t *testing.T) {
		if err := validateUpdateLockEnvelope(valid, "skill-a"); err != nil {
			t.Fatalf("validateUpdateLockEnvelope(explicit name) error = %v", err)
		}
		if err := validateUpdateLockEnvelope(valid, ""); err != nil {
			t.Fatalf("validateUpdateLockEnvelope(empty expected name) error = %v", err)
		}
	})

	t.Run("envelope rejects invalid findings summary", func(t *testing.T) {
		mut := valid
		mut.Findings.Critical = -1
		if err := validateUpdateLockEnvelope(mut, "skill-a"); err == nil || !strings.Contains(err.Error(), "findings summary") {
			t.Fatalf("expected findings-summary error, got %v", err)
		}
	})

	t.Run("envelope rejects invalid severity override audit", func(t *testing.T) {
		mut := valid
		mut.Policy.SeverityOverrides = []severityOverrideAudit{
			{
				RuleID:            "bad-rule",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "test",
				ApprovedBy:        "reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		}
		if err := validateUpdateLockEnvelope(mut, "skill-a"); err == nil || !strings.Contains(err.Error(), "severity_overrides") {
			t.Fatalf("expected severity-override error, got %v", err)
		}
	})

	t.Run("skill snapshot validates all failure branches", func(t *testing.T) {
		if err := validateUpdateLockSkillSnapshot(valid); err != nil {
			t.Fatalf("validateUpdateLockSkillSnapshot(valid) error = %v", err)
		}

		clone := func(in installLock) installLock {
			out := in
			out.Skill.Files = append([]lockFileHash(nil), in.Skill.Files...)
			return out
		}

		mut := clone(valid)
		mut.Skill.RootSHA256 = "bad"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "root_sha256") {
			t.Fatalf("expected root digest error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files = nil
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "files is empty") {
			t.Fatalf("expected empty-files error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = ""
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is empty") {
			t.Fatalf("expected empty-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "../SKILL.md"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = string([]byte{'b', 'a', 'd', 0xff})
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid non-utf8-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "SKILL.md\npayload"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid control-char-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "\u0085"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid C1-only-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "\u007f"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid DEL-only-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "\u007fSKILL.md"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid DEL-edge-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = "SKILL.md\u200d"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid unicode-obfuscation-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Path = " SKILL.md "
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file path is invalid") {
			t.Fatalf("expected invalid whitespace-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files = append(mut.Skill.Files, mut.Skill.Files[0])
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "duplicate lock file path") {
			t.Fatalf("expected duplicate-path error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].SHA256 = "bad"
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file sha256 is invalid") {
			t.Fatalf("expected file-sha error, got %v", err)
		}

		mut = clone(valid)
		mut.Skill.Files[0].Bytes = -1
		if err := validateUpdateLockSkillSnapshot(mut); err == nil || !strings.Contains(err.Error(), "file bytes is negative") {
			t.Fatalf("expected file-bytes error, got %v", err)
		}
	})
}
