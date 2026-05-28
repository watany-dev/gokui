package app

import (
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestPolicyProfileAPI(t *testing.T) {
	if got := policypkg.NormalizeProfile(" Team ").String(); got != policypkg.ProfileTeam.String() {
		t.Fatalf("NormalizeProfile() = %q, want %q", got, policypkg.ProfileTeam.String())
	}

	if _, err := policypkg.ParseProfile(policypkg.ProfileStrict.String()); err != nil {
		t.Fatal("strict should be supported")
	}
	if _, err := policypkg.ParseProfile(policypkg.ProfileTeam.String()); err != nil {
		t.Fatal("team should be supported")
	}
	if _, err := policypkg.ParseProfile(policypkg.ProfileResearch.String()); err != nil {
		t.Fatal("research should be supported")
	}
	if _, err := policypkg.ParseProfile("enterprise"); err == nil {
		t.Fatal("enterprise should not be supported")
	}
}

func TestDefaultRejectSeveritySetForProfile(t *testing.T) {
	strictSet := policypkg.ProfileStrict.DefaultRejectSeverities()
	if _, ok := strictSet["high"]; !ok {
		t.Fatal("strict set should include high")
	}
	if _, ok := strictSet["critical"]; !ok {
		t.Fatal("strict set should include critical")
	}
	researchSet := policypkg.ProfileResearch.DefaultRejectSeverities()
	if _, ok := researchSet["high"]; ok {
		t.Fatal("research set should not include high")
	}
	if _, ok := researchSet["critical"]; !ok {
		t.Fatal("research set should include critical")
	}
}

func TestEffectiveRejectSeveritySetForProfile(t *testing.T) {
	t.Run("uses defaults without policy", func(t *testing.T) {
		set, err := effectiveRejectSeverityStrings(policypkg.ProfileStrict, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("effectiveRejectSeverityStrings() error = %v", err)
		}
		if _, ok := set["critical"]; !ok {
			t.Fatal("default strict set must include critical")
		}
		if _, ok := set["high"]; !ok {
			t.Fatal("default strict set must include high")
		}
	})

	t.Run("allows policy override including medium", func(t *testing.T) {
		set, err := effectiveRejectSeverityStrings(policypkg.ProfileTeam, true, policypkg.Config{
			Profiles: map[string]policypkg.ProfileConfig{
				"team": {RejectSeverities: []string{"critical", "medium"}},
			},
		})
		if err != nil {
			t.Fatalf("effectiveRejectSeverityStrings() error = %v", err)
		}
		if _, ok := set["medium"]; !ok {
			t.Fatal("policy override set must include medium")
		}
		if _, ok := set["high"]; ok {
			t.Fatal("policy override set should not include high when omitted")
		}
	})

	t.Run("rejects profile override missing critical", func(t *testing.T) {
		_, err := effectiveRejectSeverityStrings(policypkg.ProfileResearch, true, policypkg.Config{
			Profiles: map[string]policypkg.ProfileConfig{
				"research": {RejectSeverities: []string{"high"}},
			},
		})
		if err == nil {
			t.Fatal("expected error for missing critical")
		}
	})
}

func TestShouldApplyRepositoryPolicy(t *testing.T) {
	if !shouldApplyRepositoryPolicy("local-dir") {
		t.Fatal("local-dir should allow repository policy")
	}
	if shouldApplyRepositoryPolicy("zip") {
		t.Fatal("zip should not allow repository policy")
	}
	if shouldApplyRepositoryPolicy("tar") {
		t.Fatal("tar should not allow repository policy")
	}
	if shouldApplyRepositoryPolicy("github-source") {
		t.Fatal("github-source should not allow repository policy")
	}
}
