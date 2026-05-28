package app

import policypkg "github.com/watany-dev/gokui/internal/policy"

func effectiveRejectSeverityStrings(profile policypkg.Profile, policyLoaded bool, cfg policypkg.Config) (map[string]struct{}, error) {
	set, err := policypkg.EffectiveRejectSeverities(profile, policyLoaded, cfg)
	if err != nil {
		return nil, err
	}
	return set.Strings(), nil
}
