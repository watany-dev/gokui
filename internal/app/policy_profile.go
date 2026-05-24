package app

import (
	"fmt"
	"strings"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

const (
	policyProfileStrict   = "strict"
	policyProfileTeam     = "team"
	policyProfileResearch = "research"
)

func normalizePolicyProfile(profile string) string {
	return strings.ToLower(strings.TrimSpace(profile))
}

func isSupportedPolicyProfile(profile string) bool {
	switch normalizePolicyProfile(profile) {
	case policyProfileStrict, policyProfileTeam, policyProfileResearch:
		return true
	default:
		return false
	}
}

func supportedPolicyProfilesCSV() string {
	return "strict|team|research"
}

func defaultRejectSeveritySetForProfile(profile string) map[string]struct{} {
	out := map[string]struct{}{
		"critical": {},
	}
	switch normalizePolicyProfile(profile) {
	case policyProfileStrict, policyProfileTeam:
		out["high"] = struct{}{}
	}
	return out
}

func effectiveRejectSeveritySetForProfile(profile string, policyLoaded bool, cfg policypkg.Config) (map[string]struct{}, error) {
	set := defaultRejectSeveritySetForProfile(profile)
	if !policyLoaded || len(cfg.Profiles) == 0 {
		return set, nil
	}

	overrideCfg, ok := cfg.Profiles[normalizePolicyProfile(profile)]
	if !ok {
		return set, nil
	}
	if len(overrideCfg.RejectSeverities) == 0 {
		return nil, fmt.Errorf("profile %s must define non-empty reject_severities", normalizePolicyProfile(profile))
	}

	out := make(map[string]struct{}, len(overrideCfg.RejectSeverities))
	for _, sev := range overrideCfg.RejectSeverities {
		switch sev {
		case "critical", "high", "medium", "low":
			out[sev] = struct{}{}
		default:
			return nil, fmt.Errorf("profile %s has invalid reject severity: %s", normalizePolicyProfile(profile), sev)
		}
	}
	if _, ok := out["critical"]; !ok {
		return nil, fmt.Errorf("profile %s reject_severities must include critical", normalizePolicyProfile(profile))
	}
	return out, nil
}
