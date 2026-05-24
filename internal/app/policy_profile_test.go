package app

import (
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestPolicyProfileHelpers(t *testing.T) {
	if got := normalizePolicyProfile(" Team "); got != policyProfileTeam {
		t.Fatalf("normalizePolicyProfile() = %q, want %q", got, policyProfileTeam)
	}

	if !isSupportedPolicyProfile(policyProfileStrict) {
		t.Fatal("strict should be supported")
	}
	if !isSupportedPolicyProfile(policyProfileTeam) {
		t.Fatal("team should be supported")
	}
	if !isSupportedPolicyProfile(policyProfileResearch) {
		t.Fatal("research should be supported")
	}
	if isSupportedPolicyProfile("enterprise") {
		t.Fatal("enterprise should not be supported")
	}
}

func TestDefaultRejectSeveritySetForProfile(t *testing.T) {
	strictSet := defaultRejectSeveritySetForProfile(policyProfileStrict)
	if _, ok := strictSet["high"]; !ok {
		t.Fatal("strict set should include high")
	}
	if _, ok := strictSet["critical"]; !ok {
		t.Fatal("strict set should include critical")
	}
	researchSet := defaultRejectSeveritySetForProfile(policyProfileResearch)
	if _, ok := researchSet["high"]; ok {
		t.Fatal("research set should not include high")
	}
	if _, ok := researchSet["critical"]; !ok {
		t.Fatal("research set should include critical")
	}
}

func TestEffectiveRejectSeveritySetForProfile(t *testing.T) {
	t.Run("uses defaults without policy", func(t *testing.T) {
		set, err := effectiveRejectSeveritySetForProfile(policyProfileStrict, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("effectiveRejectSeveritySetForProfile() error = %v", err)
		}
		if _, ok := set["critical"]; !ok {
			t.Fatal("default strict set must include critical")
		}
		if _, ok := set["high"]; !ok {
			t.Fatal("default strict set must include high")
		}
	})

	t.Run("allows policy override including medium", func(t *testing.T) {
		set, err := effectiveRejectSeveritySetForProfile(policyProfileTeam, true, policypkg.Config{
			Profiles: map[string]policypkg.ProfileConfig{
				"team": {RejectSeverities: []string{"critical", "medium"}},
			},
		})
		if err != nil {
			t.Fatalf("effectiveRejectSeveritySetForProfile() error = %v", err)
		}
		if _, ok := set["medium"]; !ok {
			t.Fatal("policy override set must include medium")
		}
		if _, ok := set["high"]; ok {
			t.Fatal("policy override set should not include high when omitted")
		}
	})

	t.Run("rejects profile override missing critical", func(t *testing.T) {
		_, err := effectiveRejectSeveritySetForProfile(policyProfileResearch, true, policypkg.Config{
			Profiles: map[string]policypkg.ProfileConfig{
				"research": {RejectSeverities: []string{"high"}},
			},
		})
		if err == nil {
			t.Fatal("expected error for missing critical")
		}
	})
}
