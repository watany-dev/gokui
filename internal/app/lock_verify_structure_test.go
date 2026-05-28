package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyLockStructureAndReportChecks(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "structure-report-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "structure-report-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	base, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if base.Status != "VERIFIED" {
		t.Fatalf("status = %q, want VERIFIED", base.Status)
	}
	assertCheckOK(t, base.Checks, "lock_structure")
	assertCheckOK(t, base.Checks, "install_report")

	t.Run("invalid lock structure", func(t *testing.T) {
		lockPath := filepath.Join(installedPath, installLockFile)
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		lock.Skill.Files = append(lock.Skill.Files, lockFileHash{
			Path:   lock.Skill.Files[0].Path,
			SHA256: lock.Skill.Files[0].SHA256,
			Bytes:  lock.Skill.Files[0].Bytes,
		})
		updated, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		out, err := verifyLock(installedPath)
		if err != nil {
			t.Fatalf("verifyLock() error = %v", err)
		}
		if out.Status != "DRIFTED" {
			t.Fatalf("status = %q, want DRIFTED", out.Status)
		}
		assertCheckFailedContains(t, out.Checks, "lock_structure", "duplicate lock file path")
	})
}

func TestVerifyLockStructureValidationBranches(t *testing.T) {
	valid := installLock{
		Schema:      "gokui.lock/v1",
		Name:        "x",
		InstalledAt: "2026-05-23T00:00:00Z",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/x",
			Kind:  "local-dir",
		},
		Skill: lockSkill{
			RootSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Files: []lockFileHash{
				{
					Path:   "SKILL.md",
					SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					Bytes:  10,
				},
			},
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	if ok, _ := verifyLockStructure(valid); !ok {
		t.Fatal("expected valid lock structure")
	}

	cases := []struct {
		name     string
		mutate   func(*installLock)
		detailIn string
	}{
		{
			name: "name has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Name = "x\u008f"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u0085x"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0085"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0000"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u007f"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u007fx"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Name = "x\u200d"
			},
			detailIn: "name must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = ""
			},
			detailIn: "installed_at is empty",
		},
		{
			name: "installed_at has C0/C1 control character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-23T00:00:00\u008fZ"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u00852026-05-23T00:00:00Z"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0085"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0000"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f2026-05-23T00:00:00Z"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-23T00:00:00Z\u200d"
			},
			detailIn: "installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "invalid installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = "x"
			},
			detailIn: "must be RFC3339",
		},
		{
			name: "empty profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = ""
			},
			detailIn: "policy profile is empty",
		},
		{
			name: "unsupported profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = "enterprise"
			},
			detailIn: "policy profile is unsupported",
		},
		{
			name: "policy profile has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "stric\u008ft"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085strict"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0000"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has DEL control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u007f"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u007fstrict"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "strict\u200d"
			},
			detailIn: "policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "non-canonical profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = " Strict "
			},
			detailIn: "policy profile must be canonical lowercase without surrounding whitespace",
		},
		{
			name: "invalid decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "warn"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "rejected decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "rejected"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "uppercase decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "PASS"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "policy decision has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pas\u008fs"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0085pass"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0000"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has DEL control character only",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u007f"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u007fpass"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pass\u200d"
			},
			detailIn: "lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "policy decision has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Policy.Decision = " pass "
			},
			detailIn: "lock policy decision must not contain leading or trailing whitespace",
		},
		{
			name: "invalid root hash",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = "x"
			},
			detailIn: "root_sha256 must be a canonical lowercase 64-char hex digest",
		},
		{
			name: "uppercase root hash",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
			},
			detailIn: "root_sha256 must be a canonical lowercase 64-char hex digest",
		},
		{
			name: "empty files",
			mutate: func(l *installLock) {
				l.Skill.Files = nil
			},
			detailIn: "files is empty",
		},
		{
			name: "invalid file path",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "../x"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u0085"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u0000"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has DEL control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u007f"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u007fSKILL.md"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "SKILL.md\u200d"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = " SKILL.md "
			},
			detailIn: "file path is invalid",
		},
		{
			name: "duplicate file path",
			mutate: func(l *installLock) {
				l.Skill.Files = append(l.Skill.Files, l.Skill.Files[0])
			},
			detailIn: "duplicate lock file path",
		},
		{
			name: "invalid file hash",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "x"
			},
			detailIn: "file sha256 is invalid",
		},
		{
			name: "uppercase file hash",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
			},
			detailIn: "file sha256 is invalid",
		},
		{
			name: "negative bytes",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Bytes = -1
			},
			detailIn: "bytes is negative",
		},
		{
			name: "invalid severity override entry",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides = []severityOverrideAudit{
					{
						RuleID:            "",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "test",
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
				}
			},
			detailIn: "severity_overrides is invalid",
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
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "low",
						Justification:     "second",
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T01:00:00Z",
					},
				}
			},
			detailIn: "severity_overrides is invalid",
		},
		{
			name: "negative findings summary",
			mutate: func(l *installLock) {
				l.Findings.High = -1
			},
			detailIn: "findings summary is invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := valid
			l.Skill.Files = append([]lockFileHash(nil), valid.Skill.Files...)
			tc.mutate(&l)
			ok, detail := verifyLockStructure(l)
			if ok || !strings.Contains(detail, tc.detailIn) {
				t.Fatalf("expected failure containing %q, got ok=%v detail=%q", tc.detailIn, ok, detail)
			}
		})
	}
}
