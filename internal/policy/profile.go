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
		SeverityCritical: {},
	}
	switch NormalizeProfile(p.String()) {
	case ProfileStrict, ProfileTeam:
		out[SeverityHigh] = struct{}{}
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
		severity, err := ParseSeverity(sev)
		if err != nil {
			return nil, fmt.Errorf("profile %s has invalid reject severity: %s", normalized, sev)
		}
		out[severity] = struct{}{}
	}
	if _, ok := out[SeverityCritical]; !ok {
		return nil, fmt.Errorf("profile %s reject_severities must include critical", normalized)
	}
	return out, nil
}
