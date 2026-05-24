package app

import "strings"

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

func shouldRejectSeverityForProfile(profile string, severity string) bool {
	normalizedProfile := normalizePolicyProfile(profile)
	normalizedSeverity := strings.ToLower(strings.TrimSpace(severity))
	switch normalizedProfile {
	case policyProfileResearch:
		return normalizedSeverity == "critical"
	case policyProfileStrict, policyProfileTeam:
		return normalizedSeverity == "critical" || normalizedSeverity == "high"
	default:
		// Fail closed for unknown profiles.
		return normalizedSeverity == "critical" || normalizedSeverity == "high"
	}
}
