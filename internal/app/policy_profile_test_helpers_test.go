package app

import policypkg "github.com/watany-dev/gokui/internal/policy"

const (
	policyProfileStrict   = string(policypkg.ProfileStrict)
	policyProfileTeam     = string(policypkg.ProfileTeam)
	policyProfileResearch = string(policypkg.ProfileResearch)
)

func normalizePolicyProfile(profile string) string {
	return policypkg.NormalizeProfile(profile).String()
}

func isSupportedPolicyProfile(profile string) bool {
	_, err := policypkg.ParseProfile(profile)
	return err == nil
}

func effectiveRejectSeveritySetForProfile(profile string, policyLoaded bool, cfg policypkg.Config) (map[string]struct{}, error) {
	set, err := policypkg.EffectiveRejectSeverities(policypkg.NormalizeProfile(profile), policyLoaded, cfg)
	if err != nil {
		return nil, err
	}
	return set.Strings(), nil
}
