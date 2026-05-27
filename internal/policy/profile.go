package policy

import (
	"fmt"
	"strings"
)

type Profile string

const (
	ProfileStrict   Profile = "strict"
	ProfileTeam     Profile = "team"
	ProfileResearch Profile = "research"
)

type SeveritySet map[string]struct{}

func ParseProfile(in string) (Profile, error) {
	profile := NormalizeProfile(in)
	if !profile.IsSupported() {
		return "", fmt.Errorf("unsupported profile: %s (supported: %s)", profile, SupportedProfilesCSV())
	}
	return profile, nil
}

func NormalizeProfile(in string) Profile {
	return Profile(strings.ToLower(strings.TrimSpace(in)))
}

func SupportedProfiles() []Profile {
	return []Profile{ProfileStrict, ProfileTeam, ProfileResearch}
}

func SupportedProfilesCSV() string {
	profiles := SupportedProfiles()
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.String())
	}
	return strings.Join(out, "|")
}

func (p Profile) String() string {
	return string(p)
}

func (p Profile) IsSupported() bool {
	switch NormalizeProfile(p.String()) {
	case ProfileStrict, ProfileTeam, ProfileResearch:
		return true
	default:
		return false
	}
}

func (p Profile) DefaultRejectSeverities() SeveritySet {
	out := SeveritySet{
		"critical": {},
	}
	switch NormalizeProfile(p.String()) {
	case ProfileStrict, ProfileTeam:
		out["high"] = struct{}{}
	}
	return out
}

func EffectiveRejectSeverities(profile Profile, policyLoaded bool, cfg Config) (SeveritySet, error) {
	normalized := NormalizeProfile(profile.String())
	set := normalized.DefaultRejectSeverities()
	if !policyLoaded || len(cfg.Profiles) == 0 {
		return set, nil
	}

	overrideCfg, ok := cfg.Profiles[normalized.String()]
	if !ok {
		return set, nil
	}
	if len(overrideCfg.RejectSeverities) == 0 {
		return nil, fmt.Errorf("profile %s must define non-empty reject_severities", normalized)
	}

	out := make(SeveritySet, len(overrideCfg.RejectSeverities))
	for _, sev := range overrideCfg.RejectSeverities {
		switch sev {
		case "critical", "high", "medium", "low":
			out[sev] = struct{}{}
		default:
			return nil, fmt.Errorf("profile %s has invalid reject severity: %s", normalized, sev)
		}
	}
	if _, ok := out["critical"]; !ok {
		return nil, fmt.Errorf("profile %s reject_severities must include critical", normalized)
	}
	return out, nil
}
