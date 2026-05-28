package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
	"github.com/watany-dev/gokui/internal/scan"
)

func normalizeInstallDeps(deps installDeps) installDeps {
	if deps.LoadUserPolicy == nil {
		deps.LoadUserPolicy = policypkg.LoadUserPolicy
	}
	if deps.LoadRepositoryPolicy == nil {
		deps.LoadRepositoryPolicy = policypkg.LoadRepositoryPolicy
	}
	if deps.PrepareEvaluationSource == nil {
		deps.PrepareEvaluationSource = preparePolicyEvaluationSource
	}
	return deps
}

func validateInstallOverridesPolicy(profile string, overrides []string, policyLoaded bool, cfg policypkg.Config) error {
	if len(overrides) == 0 {
		return nil
	}
	normalizedProfile := policypkg.NormalizeProfile(profile)
	if normalizedProfile == policypkg.ProfileResearch {
		return fmt.Errorf("overrides are not allowed for profile: %s", normalizedProfile)
	}
	if policyLoaded && !cfg.Overrides.Enabled {
		return fmt.Errorf("overrides are disabled by policy configuration")
	}
	if policyLoaded && len(cfg.Overrides.AllowedRuleIDs) > 0 {
		allowed := make(map[string]struct{}, len(cfg.Overrides.AllowedRuleIDs))
		for _, id := range cfg.Overrides.AllowedRuleIDs {
			allowed[id] = struct{}{}
		}
		for _, id := range overrides {
			if _, ok := allowed[id]; !ok {
				return fmt.Errorf("override rule is not allowed by policy: %s", id)
			}
		}
	}
	return nil
}

func evaluateSkillWithOverrides(skillRoot string, profile string, overrideRuleIDs []string, rejectSeveritySet map[string]struct{}) ([]inspectFinding, string, []severityOverrideAudit, error) {
	normalizedProfile := policypkg.NormalizeProfile(profile)
	if _, err := policypkg.ParseProfile(normalizedProfile.String()); err != nil {
		return nil, "", nil, fmt.Errorf("unsupported profile: %s (supported: %s)", normalizedProfile, policypkg.SupportedProfilesCSV())
	}

	scanFindings, err := scan.ScanSkillRoot(skillRoot)
	if err != nil {
		return nil, "", nil, err
	}

	findings := make([]inspectFinding, 0, len(scanFindings))
	overrides := make([]severityOverrideAudit, 0, len(overrideRuleIDs))
	overrideSet := make(map[string]struct{}, len(overrideRuleIDs))
	overrideMatched := make(map[string]struct{}, len(overrideRuleIDs))
	for _, ruleID := range overrideRuleIDs {
		overrideSet[ruleID] = struct{}{}
	}

	decision := "PASS"
	appliedAt := time.Now().UTC().Format(time.RFC3339)
	for _, finding := range scanFindings {
		findings = append(findings, inspectFinding{
			ID:       finding.ID,
			Severity: policypkg.Severity(finding.Severity),
			File:     finding.File,
			Line:     finding.Line,
			Summary:  finding.Summary,
		})
		effectiveSeverity := policypkg.Severity(finding.Severity)
		if _, ok := overrideSet[finding.ID]; ok {
			overrideMatched[finding.ID] = struct{}{}
			if effectiveSeverity == policypkg.SeverityHigh {
				effectiveSeverity = policypkg.SeverityMedium
			}
			overrides = append(overrides, severityOverrideAudit{
				RuleID:            finding.ID,
				PreviousSeverity:  finding.Severity,
				EffectiveSeverity: effectiveSeverity.String(),
				Justification:     "explicit CLI override for install policy decision",
				ApprovedBy:        "local-operator",
				Source:            "cli-override",
				AppliedAt:         appliedAt,
			})
		}
		if _, shouldReject := rejectSeveritySet[strings.ToLower(strings.TrimSpace(effectiveSeverity.String()))]; shouldReject {
			decision = reportDecisionRejected
		}
	}
	for _, ruleID := range overrideRuleIDs {
		if _, ok := overrideMatched[ruleID]; ok {
			continue
		}
		return nil, "", nil, fmt.Errorf("override rule not found in findings: %s", ruleID)
	}
	sort.Slice(overrides, func(i, j int) bool {
		return overrides[i].RuleID < overrides[j].RuleID
	})
	return findings, decision, overrides, nil
}

func resolveInstallTarget(target string) (string, error) {
	if target == "codex" {
		if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
			return filepath.Join(codexHome, "skills"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to resolve home directory for codex target: %w", err)
		}
		return filepath.Join(home, ".codex", "skills"), nil
	}

	if strings.HasPrefix(target, "custom:") {
		custom := strings.TrimSpace(strings.TrimPrefix(target, "custom:"))
		if custom == "" {
			return "", fmt.Errorf("custom target path is required: custom:/path/to/skills")
		}
		cleaned := filepath.Clean(custom)
		if !filepath.IsAbs(cleaned) {
			return "", fmt.Errorf("custom target path must be absolute: %s", custom)
		}
		return cleaned, nil
	}

	return "", fmt.Errorf("unsupported install target: %s", target)
}

func ensureInstallSourceStableFromOpen(previous os.FileInfo, opened fileInfoStatter, src string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     src,
		StatError: func(path string) error {
			return fmt.Errorf("failed to open source file: %s", path)
		},
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: install source file changed during copy: %s", rulepkg.InstallSourceChangedDuringCopy.ID, path)
		},
	}.CheckOpened(opened)
}
