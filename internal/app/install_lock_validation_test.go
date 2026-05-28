package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInstallLockForProvenanceReuse(t *testing.T) {
	sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
	valid := installLock{
		Schema:      "gokui.lock/v1",
		Name:        "skill",
		InstalledAt: "2026-05-24T00:00:00Z",
		Source: lockSource{
			Type:  "local",
			Input: sourceInput,
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
	}

	if err := validateInstallLockForProvenanceReuse(valid, "skill"); err != nil {
		t.Fatalf("validateInstallLockForProvenanceReuse(valid) error = %v", err)
	}

	cases := []struct {
		name       string
		mutate     func(*installLock)
		detailPart string
	}{
		{
			name: "schema has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Schema = "gokui.lock/v1\u008f"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Schema = "\u0085gokui.lock/v1"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C1-only control character",
			mutate: func(l *installLock) {
				l.Schema = "\u0085"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Schema = "\u0000"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character only",
			mutate: func(l *installLock) {
				l.Schema = "\u007f"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Schema = "\u007fgokui.lock/v1"
			},
			detailPart: "schema must not contain C0/C1 control characters",
		},
		{
			name: "schema has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Schema = " gokui.lock/v1 "
			},
			detailPart: "schema must not contain leading or trailing whitespace",
		},
		{
			name: "schema has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Schema = "gokui.lock/v1\u200d"
			},
			detailPart: "schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "name has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Name = " skill "
			},
			detailPart: "name must not contain leading or trailing whitespace",
		},
		{
			name: "empty installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = ""
			},
			detailPart: "installed_at is empty",
		},
		{
			name: "installed_at has surrounding whitespace",
			mutate: func(l *installLock) {
				l.InstalledAt = " 2026-05-24T00:00:00Z "
			},
			detailPart: "installed_at must not contain leading or trailing whitespace",
		},
		{
			name: "installed_at has C0/C1 control character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-24T00:00:00\u008fZ"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u00852026-05-24T00:00:00Z"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0085"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u0000"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character only",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has DEL control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u007f2026-05-24T00:00:00Z"
			},
			detailPart: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-24T00:00:00Z\u200d"
			},
			detailPart: "installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "installed_at invalid rfc3339",
			mutate: func(l *installLock) {
				l.InstalledAt = "not-rfc3339"
			},
			detailPart: "installed_at must be RFC3339",
		},
		{
			name: "name mismatch",
			mutate: func(l *installLock) {
				l.Name = "other"
			},
			detailPart: "name does not match target skill directory",
		},
		{
			name: "name has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Name = "skill\u008f"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u0085skill"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0085"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u0000"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character only",
			mutate: func(l *installLock) {
				l.Name = "\u007f"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u007fskill"
			},
			detailPart: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Name = "skill\u200d"
			},
			detailPart: "name must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "non-canonical profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = " Strict "
			},
			detailPart: "profile must be canonical lowercase without surrounding whitespace",
		},
		{
			name: "policy profile has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "stric\u008ft"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085strict"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0000"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has DEL control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u007f"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u007fstrict"
			},
			detailPart: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "strict\u200d"
			},
			detailPart: "policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "unsupported profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = "enterprise"
			},
			detailPart: "profile is unsupported",
		},
		{
			name: "non-canonical decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "PASS"
			},
			detailPart: "decision must be canonical lowercase pass",
		},
		{
			name: "policy decision has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pas\u008fs"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0085pass"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C1-only control character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0085"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0000"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has DEL control character only",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u007f"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u007fpass"
			},
			detailPart: "policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pass\u200d"
			},
			detailPart: "policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "policy decision has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Policy.Decision = " pass "
			},
			detailPart: "policy decision must not contain leading or trailing whitespace",
		},
		{
			name: "empty source kind",
			mutate: func(l *installLock) {
				l.Source.Kind = ""
			},
			detailPart: "source kind is empty",
		},
		{
			name: "source kind has whitespace",
			mutate: func(l *installLock) {
				l.Source.Kind = " local-dir "
			},
			detailPart: "source kind must not contain leading or trailing whitespace",
		},
		{
			name: "source kind uppercase",
			mutate: func(l *installLock) {
				l.Source.Kind = "LOCAL-DIR"
			},
			detailPart: "source kind must be canonical lowercase",
		},
		{
			name: "source kind has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Source.Kind = "local\u008fdir"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Source.Kind = "\u0085local-dir"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Source.Kind = "\u0085"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Source.Kind = "\u0000"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has DEL control character only",
			mutate: func(l *installLock) {
				l.Source.Kind = "\u007f"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Source.Kind = "\u007flocal-dir"
			},
			detailPart: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Source.Kind = "local-dir\u200d"
			},
			detailPart: "source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty source input",
			mutate: func(l *installLock) {
				l.Source.Input = ""
			},
			detailPart: "source input is empty",
		},
		{
			name: "source input has whitespace",
			mutate: func(l *installLock) {
				l.Source.Input = " " + l.Source.Input + " "
			},
			detailPart: "source input must not contain leading or trailing whitespace",
		},
		{
			name: "source input has control character",
			mutate: func(l *installLock) {
				l.Source.Input = sourceInput + "\npayload"
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C1 control character",
			mutate: func(l *installLock) {
				l.Source.Input = sourceInput + "\u0085payload"
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C1 control character at edge",
			mutate: func(l *installLock) {
				l.Source.Input = "\u0085" + sourceInput
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C1 control character only",
			mutate: func(l *installLock) {
				l.Source.Input = "\u0085"
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Source.Input = "\u0000"
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has DEL control character only",
			mutate: func(l *installLock) {
				l.Source.Input = "\u007f"
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Source.Input = "\u007f" + sourceInput
			},
			detailPart: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Source.Input = sourceInput + "\u200dpayload"
			},
			detailPart: "source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "source kind mismatch",
			mutate: func(l *installLock) {
				l.Source.Kind = "github-source"
			},
			detailPart: "source kind does not match source input",
		},
		{
			name: "invalid source type",
			mutate: func(l *installLock) {
				l.Source.Type = "LOCAL"
			},
			detailPart: "source type must be canonical lowercase",
		},
		{
			name: "empty source type",
			mutate: func(l *installLock) {
				l.Source.Type = ""
			},
			detailPart: "source type is empty",
		},
		{
			name: "source type has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Source.Type = "loca\u008fl"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Source.Type = "\u0085local"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has C1-only control character",
			mutate: func(l *installLock) {
				l.Source.Type = "\u0085"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Source.Type = "\u0000"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has DEL control character only",
			mutate: func(l *installLock) {
				l.Source.Type = "\u007f"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has DEL control character at edge",
			mutate: func(l *installLock) {
				l.Source.Type = "\u007flocal"
			},
			detailPart: "source type must not contain C0/C1 control characters",
		},
		{
			name: "source type has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Source.Type = "local\u200d"
			},
			detailPart: "source type must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "source type mismatch",
			mutate: func(l *installLock) {
				l.Source.Type = "archive"
			},
			detailPart: "source type mismatch for kind",
		},
		{
			name: "non-canonical local source path",
			mutate: func(l *installLock) {
				l.Source.Input = sourceInput + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(sourceInput)
			},
			detailPart: "source input must be a canonical cleaned path for local/archive sources",
		},
		{
			name: "invalid severity override entry",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].RuleID = ""
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override rule_id has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].RuleID = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
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
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override approved_by has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].ApprovedBy = " reviewer "
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override approved_by has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].ApprovedBy = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override previous_severity has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].PreviousSeverity = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override effective_severity has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].EffectiveSeverity = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override justification has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].Justification = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override justification has bidi control",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].Justification = "approved\u202E"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override source has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].Source = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "severity override applied_at has C0 NUL control character",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides[0].AppliedAt = "\u0000"
			},
			detailPart: "severity_overrides is invalid",
		},
		{
			name: "negative findings summary",
			mutate: func(l *installLock) {
				l.Findings.High = -1
			},
			detailPart: "findings summary is invalid",
		},
		{
			name: "non-canonical root digest",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = strings.Repeat("A", 64)
			},
			detailPart: "root_sha256 must be a canonical lowercase 64-char hex digest",
		},
		{
			name: "empty lock files",
			mutate: func(l *installLock) {
				l.Skill.Files = nil
			},
			detailPart: "skill files is empty",
		},
		{
			name: "invalid lock file path",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "../SKILL.md"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "non-utf8 lock file path",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = string([]byte{'b', 'a', 'd', 0xff})
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path contains control character",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "SKILL.md\npayload"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path contains C1 control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u0085"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path contains C0 NUL control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u0000"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path contains DEL control character only",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u007f"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path contains DEL control character at edge",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "\u007fSKILL.md"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "SKILL.md\u200d"
			},
			detailPart: "file path is invalid",
		},
		{
			name: "lock file path has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = " SKILL.md "
			},
			detailPart: "file path is invalid",
		},
		{
			name: "duplicate lock file path",
			mutate: func(l *installLock) {
				l.Skill.Files = append(l.Skill.Files, l.Skill.Files[0])
			},
			detailPart: "duplicate lock file path",
		},
		{
			name: "invalid lock file digest",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "bad"
			},
			detailPart: "file sha256 is invalid",
		},
		{
			name: "negative lock file bytes",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Bytes = -1
			},
			detailPart: "file bytes is negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := valid
			mut.Skill.Files = append([]lockFileHash(nil), valid.Skill.Files...)
			mut.Policy.SeverityOverrides = append([]severityOverrideAudit(nil), valid.Policy.SeverityOverrides...)
			tc.mutate(&mut)
			err := validateInstallLockForProvenanceReuse(mut, "skill")
			if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
				t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
			}
		})
	}

	githubValid := valid
	githubValid.Name = "github-skill"
	githubValid.Source = lockSource{
		Type:  "github",
		Input: "github:org/repo//skills/github-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		Kind:  "github-source",
	}
	if err := validateInstallLockForProvenanceReuse(githubValid, "github-skill"); err != nil {
		t.Fatalf("validateInstallLockForProvenanceReuse(github valid) error = %v", err)
	}

	t.Run("github source must be canonical", func(t *testing.T) {
		mut := githubValid
		mut.Source.Input = "github:org/repo//skills/./github-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		err := validateInstallLockForProvenanceReuse(mut, "github-skill")
		if err == nil || !strings.Contains(err.Error(), "invalid github source input in lock") {
			t.Fatalf("expected github canonical-path syntax error, got %v", err)
		}
	})

	t.Run("github source must be commit pinned", func(t *testing.T) {
		mut := githubValid
		mut.Source.Input = "github:org/repo//skills/github-skill@main"
		err := validateInstallLockForProvenanceReuse(mut, "github-skill")
		if err == nil || !strings.Contains(err.Error(), "github lock source must be commit-pinned") {
			t.Fatalf("expected github commit-pin error, got %v", err)
		}
	})

	t.Run("github source syntax must be valid", func(t *testing.T) {
		mut := githubValid
		mut.Source.Input = "github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		err := validateInstallLockForProvenanceReuse(mut, "github-skill")
		if err == nil || !strings.Contains(err.Error(), "invalid github source input in lock") {
			t.Fatalf("expected github source syntax error, got %v", err)
		}
	})

	t.Run("github source path surrounding spaces must be invalid", func(t *testing.T) {
		mut := githubValid
		mut.Source.Input = "github:org/repo// skills/github-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		err := validateInstallLockForProvenanceReuse(mut, "github-skill")
		if err == nil || !strings.Contains(err.Error(), "invalid github source input in lock") {
			t.Fatalf("expected github source path-space syntax error, got %v", err)
		}
	})

	t.Run("github source non-canonical path segments must be invalid", func(t *testing.T) {
		mut := githubValid
		mut.Source.Input = "github:org/repo//skills//github-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		err := validateInstallLockForProvenanceReuse(mut, "github-skill")
		if err == nil || !strings.Contains(err.Error(), "invalid github source input in lock") {
			t.Fatalf("expected github source non-canonical path syntax error, got %v", err)
		}
	})
}
