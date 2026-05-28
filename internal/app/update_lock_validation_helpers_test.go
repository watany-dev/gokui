package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestValidateUpdateLockPolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      lockPolicy
		wantProfile string
		wantErrPart string
	}{
		{name: "valid strict pass policy", policy: lockPolicy{Profile: policyProfileStrict, Decision: "pass"}, wantProfile: policyProfileStrict},
		{name: "profile control character", policy: lockPolicy{Profile: policyProfileStrict + "\n", Decision: "pass"}, wantErrPart: "lock policy profile must not contain C0/C1 control characters"},
		{name: "profile unicode obfuscation", policy: lockPolicy{Profile: policyProfileStrict + "\u200d", Decision: "pass"}, wantErrPart: "lock policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters"},
		{name: "profile not canonical", policy: lockPolicy{Profile: "Strict", Decision: "pass"}, wantErrPart: "lock policy profile must be canonical lowercase without surrounding whitespace"},
		{name: "unsupported profile", policy: lockPolicy{Profile: "unknown", Decision: "pass"}, wantErrPart: "unsupported policy profile in lockfile: unknown"},
		{name: "decision control character", policy: lockPolicy{Profile: policyProfileStrict, Decision: "pass\n"}, wantErrPart: "lock policy decision must not contain C0/C1 control characters"},
		{name: "decision unicode obfuscation", policy: lockPolicy{Profile: policyProfileStrict, Decision: "pass\u200d"}, wantErrPart: "lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters"},
		{name: "decision surrounding whitespace", policy: lockPolicy{Profile: policyProfileStrict, Decision: " pass"}, wantErrPart: "lock policy decision must not contain leading or trailing whitespace"},
		{name: "decision not pass", policy: lockPolicy{Profile: policyProfileStrict, Decision: "PASS"}, wantErrPart: "lock policy decision must be canonical lowercase pass"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProfile, err := validateUpdateLockPolicy(tt.policy)
			assertValidationErr(t, err, tt.wantErrPart)
			if err == nil && gotProfile != tt.wantProfile {
				t.Fatalf("profile = %q, want %q", gotProfile, tt.wantProfile)
			}
		})
	}
}

func TestValidateUpdateLockSource(t *testing.T) {
	sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "skill"))
	githubSource := "github:org/repo//skills/example@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"

	tests := []struct {
		name        string
		source      lockSource
		wantInput   string
		wantKind    string
		wantStatus  string
		wantCode    string
		wantMessage string
	}{
		{name: "valid local source", source: lockSource{Type: "local", Input: sourceInput, Kind: "local-dir"}, wantInput: sourceInput, wantKind: "local-dir"},
		{name: "valid github source", source: lockSource{Type: "github", Input: githubSource, Kind: "github-source"}, wantInput: githubSource, wantKind: "github-source"},
		{name: "input control character", source: lockSource{Type: "local", Input: sourceInput + "\n", Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source input must not contain C0/C1 control characters"},
		{name: "input unicode obfuscation", source: lockSource{Type: "local", Input: sourceInput + "\u200d", Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters"},
		{name: "input empty", source: lockSource{Type: "local", Input: "", Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source input is empty"},
		{name: "input surrounding whitespace", source: lockSource{Type: "local", Input: " " + sourceInput, Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source input must not contain leading or trailing whitespace"},
		{name: "kind empty", source: lockSource{Type: "local", Input: sourceInput, Kind: ""}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source kind is empty"},
		{name: "kind uppercase", source: lockSource{Type: "local", Input: sourceInput, Kind: "Local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source kind must be canonical lowercase"},
		{name: "unsupported kind", source: lockSource{Type: "local", Input: sourceInput, Kind: "unsupported"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "unsupported source kind in lockfile: unsupported"},
		{name: "local input not cleaned", source: lockSource{Type: "local", Input: sourceInput + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(sourceInput), Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source input must be a canonical cleaned path for local/archive sources"},
		{name: "kind does not match detected source", source: lockSource{Type: "archive", Input: sourceInput, Kind: "zip"}, wantStatus: "ERROR", wantCode: updateCodeSourceMetadataBad, wantMessage: "lock source kind does not match source input"},
		{name: "type empty", source: lockSource{Type: "", Input: sourceInput, Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source type is empty"},
		{name: "type uppercase", source: lockSource{Type: "Local", Input: sourceInput, Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "lock source type must be canonical lowercase"},
		{name: "type mismatch", source: lockSource{Type: "archive", Input: sourceInput, Kind: "local-dir"}, wantStatus: "ERROR", wantCode: updateCodeLockfileInvalid, wantMessage: "source type mismatch for kind local-dir: expected local, got archive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotInput, gotKind, failure := validateUpdateLockSource(tt.source)
			if tt.wantMessage == "" {
				if failure != nil {
					t.Fatalf("failure = %+v, want nil", failure)
				}
				if gotInput != tt.wantInput {
					t.Fatalf("input = %q, want %q", gotInput, tt.wantInput)
				}
				if gotKind != tt.wantKind {
					t.Fatalf("kind = %q, want %q", gotKind, tt.wantKind)
				}
				return
			}
			if failure == nil {
				t.Fatal("failure = nil, want validation failure")
			}
			if failure.status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", failure.status, tt.wantStatus)
			}
			if failure.code != tt.wantCode {
				t.Fatalf("code = %q, want %q", failure.code, tt.wantCode)
			}
			if !strings.Contains(failure.message, tt.wantMessage) {
				t.Fatalf("message = %q, want to contain %q", failure.message, tt.wantMessage)
			}
		})
	}
}

func TestEvaluateUpdateFindings(t *testing.T) {
	configured := []severityOverrideAudit{
		{RuleID: "RULE_B", PreviousSeverity: "high", EffectiveSeverity: "medium", Justification: "accepted", ApprovedBy: "reviewer", Source: "cli-override", AppliedAt: "2026-01-02T00:00:00Z"},
		{RuleID: "RULE_A", PreviousSeverity: "high", EffectiveSeverity: "medium", Justification: "accepted", ApprovedBy: "reviewer", Source: "cli-override", AppliedAt: "2026-01-01T00:00:00Z"},
	}
	rejectHigh := map[string]struct{}{"high": {}}

	tests := []struct {
		name          string
		findings      []inspectFinding
		wantDecision  string
		wantOverrides []string
		wantAdded     []string
		wantRemoved   []string
	}{
		{
			name:          "active high override downgrades decision",
			findings:      []inspectFinding{{ID: "RULE_A", Severity: "high"}},
			wantDecision:  "PASS",
			wantOverrides: []string{"RULE_A"},
			wantRemoved:   []string{"RULE_B"},
		},
		{
			name:          "configured override for non-high finding is still active",
			findings:      []inspectFinding{{ID: "RULE_A", Severity: "medium"}},
			wantDecision:  "PASS",
			wantOverrides: []string{"RULE_A"},
			wantRemoved:   []string{"RULE_B"},
		},
		{
			name:         "unoverridden high finding rejects",
			findings:     []inspectFinding{{ID: "RULE_C", Severity: "high"}},
			wantDecision: "REJECTED",
			wantRemoved:  []string{"RULE_A", "RULE_B"},
		},
		{
			name:          "all configured overrides remain active",
			findings:      []inspectFinding{{ID: "RULE_B", Severity: "high"}, {ID: "RULE_A", Severity: "high"}},
			wantDecision:  "PASS",
			wantOverrides: []string{"RULE_A", "RULE_B"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateUpdateFindings(tt.findings, configured, rejectHigh)
			if got.decision != tt.wantDecision {
				t.Fatalf("decision = %q, want %q", got.decision, tt.wantDecision)
			}
			if gotOverrideIDs := overrideRuleIDs(got.severityOverrides); strings.Join(gotOverrideIDs, ",") != strings.Join(tt.wantOverrides, ",") {
				t.Fatalf("severity overrides = %+v, want %v", gotOverrideIDs, tt.wantOverrides)
			}
			if strings.Join(got.severityOverrideDiff.Added, ",") != strings.Join(tt.wantAdded, ",") {
				t.Fatalf("added diff = %v, want %v", got.severityOverrideDiff.Added, tt.wantAdded)
			}
			if strings.Join(got.severityOverrideDiff.Removed, ",") != strings.Join(tt.wantRemoved, ",") {
				t.Fatalf("removed diff = %v, want %v", got.severityOverrideDiff.Removed, tt.wantRemoved)
			}
		})
	}
}

func TestFinalizeUpdateSkillStatus(t *testing.T) {
	tests := []struct {
		name        string
		item        updateSkillItem
		wantStatus  string
		wantCode    string
		wantMessage string
	}{
		{
			name:        "rejected decision wins",
			item:        updateSkillItem{Decision: "REJECTED", Diff: updateDiff{Added: []string{"new.md"}}},
			wantStatus:  "REJECTED",
			wantCode:    updateCodePolicyRejected,
			wantMessage: "fresh policy evaluation rejected update source",
		},
		{
			name:        "content diff changed",
			item:        updateSkillItem{Decision: "PASS", Diff: updateDiff{Changed: []string{"SKILL.md"}}},
			wantStatus:  "CHANGED",
			wantCode:    updateCodeChanged,
			wantMessage: "update source differs from installed lock snapshot",
		},
		{
			name:        "risk delta changed",
			item:        updateSkillItem{Decision: "PASS", Risk: updateRisk{Delta: lockFindingSummary{High: 1}}},
			wantStatus:  "CHANGED",
			wantCode:    updateCodeChanged,
			wantMessage: "update source differs from installed lock snapshot",
		},
		{
			name:        "new url changed",
			item:        updateSkillItem{Decision: "PASS", NewURLs: []string{"https://example.test"}},
			wantStatus:  "CHANGED",
			wantCode:    updateCodeChanged,
			wantMessage: "update source differs from installed lock snapshot",
		},
		{
			name:        "override diff changed",
			item:        updateSkillItem{Decision: "PASS", SeverityOverrideDiff: updateSeverityOverrideDiff{Removed: []string{"RULE_A"}}},
			wantStatus:  "CHANGED",
			wantCode:    updateCodeChanged,
			wantMessage: "update source differs from installed lock snapshot",
		},
		{
			name:        "no change",
			item:        updateSkillItem{Decision: "PASS"},
			wantStatus:  "UP_TO_DATE",
			wantCode:    updateCodeUpToDate,
			wantMessage: "no change detected against installed lock snapshot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finalizeUpdateSkillStatus(tt.item)
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if got.ErrorCode != tt.wantCode {
				t.Fatalf("error code = %q, want %q", got.ErrorCode, tt.wantCode)
			}
			if got.Message != tt.wantMessage {
				t.Fatalf("message = %q, want %q", got.Message, tt.wantMessage)
			}
		})
	}
}

func TestEvaluateUpdateRisk(t *testing.T) {
	previous := lockFindingSummary{Critical: 1, High: 2, Medium: 3, Low: 4}
	item := updateSkillItem{
		Diff: updateDiff{
			Added:   []string{"new.md"},
			Removed: []string{"old.md"},
			Changed: []string{"SKILL.md"},
		},
		NewURLs:            []string{"https://example.test"},
		NewExecutableFiles: []string{"scripts/run.sh", "bin/tool"},
		SeverityOverrideDiff: updateSeverityOverrideDiff{
			Added:   []string{"RULE_A"},
			Removed: []string{"RULE_B", "RULE_C"},
		},
	}
	findings := []inspectFinding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "low"},
	}

	got := evaluateUpdateRisk(previous, findings, item)
	wantCurrent := lockFindingSummary{Critical: 1, High: 1, Low: 1}
	if got.risk.Previous != previous {
		t.Fatalf("previous risk = %+v, want %+v", got.risk.Previous, previous)
	}
	if got.risk.Current != wantCurrent {
		t.Fatalf("current risk = %+v, want %+v", got.risk.Current, wantCurrent)
	}
	wantDelta := lockFindingSummary{Critical: 0, High: -1, Medium: -3, Low: -3}
	if got.risk.Delta != wantDelta {
		t.Fatalf("risk delta = %+v, want %+v", got.risk.Delta, wantDelta)
	}

	wantSignals := updateSignalScore(updateRiskSignalInputs{
		NewURLs:         1,
		NewExecutables:  2,
		FileDelta:       3,
		OverrideAdded:   1,
		OverrideRemoved: 2,
	})
	if got.score.Signals != wantSignals {
		t.Fatalf("risk score signals = %d, want %d", got.score.Signals, wantSignals)
	}
	if got.score.Model != updateRiskScoreModel {
		t.Fatalf("risk score model = %q, want %q", got.score.Model, updateRiskScoreModel)
	}
	if got.score.Current != severityWeightedScore(wantCurrent)+wantSignals {
		t.Fatalf("risk score current = %d, want severity+signals", got.score.Current)
	}
	if got.score.Previous != severityWeightedScore(previous) {
		t.Fatalf("risk score previous = %d, want %d", got.score.Previous, severityWeightedScore(previous))
	}
}

func TestEvaluateUpdateFileDiff(t *testing.T) {
	previous := []lockFileHash{
		{Path: "SKILL.md", SHA256: strings.Repeat("a", 64), Bytes: 10},
		{Path: "removed.md", SHA256: strings.Repeat("b", 64), Bytes: 20},
		{Path: "changed.md", SHA256: strings.Repeat("c", 64), Bytes: 30},
		{Path: installLockFile, SHA256: strings.Repeat("d", 64), Bytes: 40},
	}
	current := []lockFileHash{
		{Path: "SKILL.md", SHA256: strings.Repeat("a", 64), Bytes: 10},
		{Path: "changed.md", SHA256: strings.Repeat("e", 64), Bytes: 30},
		{Path: "added.md", SHA256: strings.Repeat("f", 64), Bytes: 50},
	}
	exclude := map[string]struct{}{
		installLockFile: {},
	}

	got := evaluateUpdateFileDiff(previous, current, exclude)
	if strings.Join(got.Added, ",") != "added.md" {
		t.Fatalf("added = %v, want [added.md]", got.Added)
	}
	if strings.Join(got.Removed, ",") != "removed.md" {
		t.Fatalf("removed = %v, want [removed.md]", got.Removed)
	}
	if strings.Join(got.Changed, ",") != "changed.md" {
		t.Fatalf("changed = %v, want [changed.md]", got.Changed)
	}
}

func TestCollectUpdateSignals(t *testing.T) {
	installedRoot := filepath.Join(t.TempDir(), "installed")
	currentRoot := filepath.Join(t.TempDir(), "current")
	if err := os.MkdirAll(filepath.Join(installedRoot, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir installed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(currentRoot, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir current: %v", err)
	}

	if err := os.WriteFile(filepath.Join(installedRoot, "SKILL.md"), []byte("[old](https://old.example.test)\n"), 0o644); err != nil {
		t.Fatalf("write installed skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentRoot, "SKILL.md"), []byte("[old](https://old.example.test)\n[new](https://new.example.test)\n"), 0o644); err != nil {
		t.Fatalf("write current skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(installedRoot, "scripts", "existing.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write installed executable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentRoot, "scripts", "existing.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write current executable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentRoot, "scripts", "new.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write new executable: %v", err)
	}

	got, err := collectUpdateSignals(installedRoot, currentRoot)
	if err != nil {
		t.Fatalf("collectUpdateSignals() error = %v", err)
	}
	if strings.Join(got.newURLs, ",") != "https://new.example.test" {
		t.Fatalf("new urls = %v, want [https://new.example.test]", got.newURLs)
	}
	if strings.Join(got.newExecutableFiles, ",") != "scripts/new.sh" {
		t.Fatalf("new executable files = %v, want [scripts/new.sh]", got.newExecutableFiles)
	}
}

func TestValidateUpdateGitHubSource(t *testing.T) {
	validPinned := "github:org/repo//skills/example@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"

	tests := []struct {
		name        string
		installed   string
		sourceInput string
		kind        string
		wantStatus  string
		wantCode    string
		wantMessage string
	}{
		{
			name:        "non github source skips validation",
			installed:   t.TempDir(),
			sourceInput: filepath.Join(t.TempDir(), "skill"),
			kind:        "local-dir",
		},
		{
			name:        "invalid github source",
			installed:   t.TempDir(),
			sourceInput: "github:bad",
			kind:        "github-source",
			wantStatus:  "ERROR",
			wantCode:    updateCodeGitHubSourceBad,
			wantMessage: "invalid github source in lockfile",
		},
		{
			name:        "floating github ref",
			installed:   t.TempDir(),
			sourceInput: "github:org/repo//skills/example@main",
			kind:        "github-source",
			wantStatus:  "REJECTED",
			wantCode:    updateCodeGitHubRefFloating,
			wantMessage: "floating github refs are not eligible for update",
		},
		{
			name:        "missing metadata is source metadata error",
			installed:   t.TempDir(),
			sourceInput: validPinned,
			kind:        "github-source",
			wantStatus:  "ERROR",
			wantCode:    updateCodeSourceMetadataBad,
			wantMessage: "source metadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateUpdateGitHubSource(tt.installed, tt.sourceInput, tt.kind)
			if tt.wantMessage == "" {
				if got != nil {
					t.Fatalf("failure = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("failure = nil, want validation failure")
			}
			if got.status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", got.status, tt.wantStatus)
			}
			if got.code != tt.wantCode {
				t.Fatalf("code = %q, want %q", got.code, tt.wantCode)
			}
			if !strings.Contains(got.message, tt.wantMessage) {
				t.Fatalf("message = %q, want to contain %q", got.message, tt.wantMessage)
			}
		})
	}
}

func TestResolveUpdateEvaluationPolicy(t *testing.T) {
	base := policypkg.Config{
		Profiles: map[string]policypkg.ProfileConfig{
			"strict": {RejectSeverities: []string{"critical", "high"}},
		},
	}

	localRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(localRoot, ".gokui-policy.toml"), []byte("[profiles.strict]\nreject_severities = [\"critical\"]\n"), 0o644); err != nil {
		t.Fatalf("write repo policy: %v", err)
	}
	gotConfig, gotLoaded, err := resolveUpdateEvaluationPolicy("local-dir", localRoot, true, base)
	if err != nil {
		t.Fatalf("resolveUpdateEvaluationPolicy(local-dir) error = %v", err)
	}
	if !gotLoaded {
		t.Fatal("repo policy should mark effective policy as loaded")
	}
	if strings.Join(gotConfig.Profiles["strict"].RejectSeverities, ",") != "critical" {
		t.Fatalf("repo policy did not override reject severities: %+v", gotConfig.Profiles["strict"].RejectSeverities)
	}

	gotConfig, gotLoaded, err = resolveUpdateEvaluationPolicy("github-source", localRoot, true, base)
	if err != nil {
		t.Fatalf("resolveUpdateEvaluationPolicy(github-source) error = %v", err)
	}
	if !gotLoaded {
		t.Fatal("existing loaded state should be preserved for github-source")
	}
	if strings.Join(gotConfig.Profiles["strict"].RejectSeverities, ",") != "critical,high" {
		t.Fatalf("github-source should preserve base policy: %+v", gotConfig.Profiles["strict"].RejectSeverities)
	}

	emptyRoot := t.TempDir()
	gotConfig, gotLoaded, err = resolveUpdateEvaluationPolicy("local-dir", emptyRoot, false, base)
	if err != nil {
		t.Fatalf("resolveUpdateEvaluationPolicy(no repo policy) error = %v", err)
	}
	if gotLoaded {
		t.Fatal("loaded state should remain false without repo policy")
	}
	if strings.Join(gotConfig.Profiles["strict"].RejectSeverities, ",") != "critical,high" {
		t.Fatalf("no repo policy should preserve base policy: %+v", gotConfig.Profiles["strict"].RejectSeverities)
	}

	invalidRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(invalidRoot, ".gokui-policy.toml"), []byte("unknown_key = 1\n"), 0o644); err != nil {
		t.Fatalf("write invalid repo policy: %v", err)
	}
	if _, _, err := resolveUpdateEvaluationPolicy("local-dir", invalidRoot, false, base); err == nil {
		t.Fatal("expected invalid repository policy error")
	}
}

func TestValidateUpdateLockForEvaluation(t *testing.T) {
	installedPath := t.TempDir()
	sourceInput := filepath.Clean(filepath.Join(t.TempDir(), "source-skill"))
	validLock := installLock{
		Schema:      lockSchemaVersion,
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
				{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 10},
			},
		},
		Policy: lockPolicy{
			Profile:  policyProfileStrict,
			Decision: "pass",
		},
	}
	item := updateSkillItem{Name: "skill", Path: installedPath}

	got, failure := validateUpdateLockForEvaluation(item, validLock)
	if failure != nil {
		t.Fatalf("validateUpdateLockForEvaluation() failure = %+v", failure)
	}
	if got.policyProfile != policyProfileStrict {
		t.Fatalf("policy profile = %q, want %q", got.policyProfile, policyProfileStrict)
	}
	if got.sourceInput != sourceInput {
		t.Fatalf("source input = %q, want %q", got.sourceInput, sourceInput)
	}
	if got.kind != "local-dir" {
		t.Fatalf("kind = %q, want local-dir", got.kind)
	}

	invalid := validLock
	invalid.Name = "other"
	_, failure = validateUpdateLockForEvaluation(item, invalid)
	if failure == nil {
		t.Fatal("expected name mismatch failure")
	}
	if failure.status != "ERROR" || failure.code != updateCodeLockfileInvalid {
		t.Fatalf("failure = %+v, want lockfile invalid error", failure)
	}
	if !strings.Contains(failure.message, "lock name does not match installed skill directory") {
		t.Fatalf("failure message = %q", failure.message)
	}
}

func TestEvaluateUpdateSourceFindings(t *testing.T) {
	t.Run("invalid reject severity returns evaluation failure", func(t *testing.T) {
		cfg := policypkg.Config{
			Profiles: map[string]policypkg.ProfileConfig{
				policyProfileStrict: {RejectSeverities: []string{"urgent"}},
			},
		}
		got, err := evaluateUpdateSourceFindings(t.TempDir(), policyProfileStrict, true, cfg, nil)
		if err != nil {
			t.Fatalf("evaluateUpdateSourceFindings() error = %v", err)
		}
		if got.failure == nil {
			t.Fatal("failure = nil, want evaluation failure")
		}
		if got.failure.status != "ERROR" || got.failure.code != updateCodeEvaluationError {
			t.Fatalf("failure = %+v, want evaluation error", got.failure)
		}
		if !strings.Contains(got.failure.message, "invalid reject severity") {
			t.Fatalf("failure message = %q, want invalid reject severity detail", got.failure.message)
		}
	})

	t.Run("clean source evaluates pass", func(t *testing.T) {
		skillRoot := createSkillSourceForInstallTest(t, "clean-update-source")
		got, err := evaluateUpdateSourceFindings(skillRoot, policyProfileStrict, false, policypkg.Config{}, nil)
		if err != nil {
			t.Fatalf("evaluateUpdateSourceFindings() error = %v", err)
		}
		if got.failure != nil {
			t.Fatalf("failure = %+v, want nil", got.failure)
		}
		if got.decision != "PASS" {
			t.Fatalf("decision = %q, want PASS", got.decision)
		}
		if len(got.findings) != 0 {
			t.Fatalf("findings length = %d, want 0", len(got.findings))
		}
		if len(got.severityOverrides) != 0 {
			t.Fatalf("severity overrides length = %d, want 0", len(got.severityOverrides))
		}
	})
}

func TestEvaluateUpdateSourceChanges(t *testing.T) {
	installedRoot := filepath.Join(t.TempDir(), "installed")
	currentRoot := filepath.Join(t.TempDir(), "current")
	if err := os.MkdirAll(filepath.Join(installedRoot, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir installed scripts: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(currentRoot, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir current scripts: %v", err)
	}
	installedSkill := []byte("---\nname: source-change\ndescription: installed\n---\n[old](https://old.example.test)\n")
	currentSkill := []byte("---\nname: source-change\ndescription: current\n---\n[old](https://old.example.test)\n[new](https://new.example.test)\n")
	if err := os.WriteFile(filepath.Join(installedRoot, "SKILL.md"), installedSkill, 0o644); err != nil {
		t.Fatalf("write installed skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentRoot, "SKILL.md"), currentSkill, 0o644); err != nil {
		t.Fatalf("write current skill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(currentRoot, "scripts", "new.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write current executable: %v", err)
	}

	installedFiles, _, err := buildFileDigestsFiltered(installedRoot, map[string]struct{}{})
	if err != nil {
		t.Fatalf("build installed digests: %v", err)
	}
	item := updateSkillItem{
		Path: installedRoot,
		Findings: []inspectFinding{
			{Severity: "high"},
		},
	}
	lock := installLock{
		Skill: lockSkill{Files: installedFiles},
		Findings: lockFindingSummary{
			High: 2,
		},
	}

	got, err := evaluateUpdateSourceChanges(item, lock, currentRoot)
	if err != nil {
		t.Fatalf("evaluateUpdateSourceChanges() error = %v", err)
	}
	if strings.Join(got.Diff.Changed, ",") != "SKILL.md" {
		t.Fatalf("changed diff = %v, want [SKILL.md]", got.Diff.Changed)
	}
	if strings.Join(got.Diff.Added, ",") != "scripts/new.sh" {
		t.Fatalf("added diff = %v, want [scripts/new.sh]", got.Diff.Added)
	}
	if strings.Join(got.NewURLs, ",") != "https://new.example.test" {
		t.Fatalf("new urls = %v, want [https://new.example.test]", got.NewURLs)
	}
	if strings.Join(got.NewExecutableFiles, ",") != "scripts/new.sh" {
		t.Fatalf("new executable files = %v, want [scripts/new.sh]", got.NewExecutableFiles)
	}
	if got.Risk.Delta.High != -1 {
		t.Fatalf("risk high delta = %d, want -1", got.Risk.Delta.High)
	}
	if got.RiskScore.Model != updateRiskScoreModel {
		t.Fatalf("risk score model = %q, want %q", got.RiskScore.Model, updateRiskScoreModel)
	}
}

func overrideRuleIDs(overrides []severityOverrideAudit) []string {
	out := make([]string, 0, len(overrides))
	for _, override := range overrides {
		out = append(out, override.RuleID)
	}
	return out
}

func assertValidationErr(t *testing.T, err error, wantErrPart string) {
	t.Helper()
	if wantErrPart == "" {
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("err = nil, want %q", wantErrPart)
	}
	if !strings.Contains(err.Error(), wantErrPart) {
		t.Fatalf("err = %v, want to contain %q", err, wantErrPart)
	}
}
