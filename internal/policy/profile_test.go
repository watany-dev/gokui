package policy

import "testing"

func TestProfileHelpers(t *testing.T) {
	if got := NormalizeProfile(" Team "); got != ProfileTeam {
		t.Fatalf("NormalizeProfile() = %q, want %q", got, ProfileTeam)
	}
	if got := ProfileStrict.String(); got != "strict" {
		t.Fatalf("ProfileStrict.String() = %q", got)
	}
	if !ProfileStrict.IsSupported() || !ProfileTeam.IsSupported() || !ProfileResearch.IsSupported() {
		t.Fatal("built-in profiles should be supported")
	}
	if NormalizeProfile("enterprise").IsSupported() {
		t.Fatal("enterprise should not be supported")
	}
	if got, err := ParseProfile(" strict "); err != nil || got != ProfileStrict {
		t.Fatalf("ParseProfile(strict) = %q, %v", got, err)
	}
	if _, err := ParseProfile("enterprise"); err == nil {
		t.Fatal("ParseProfile should reject unsupported profile")
	}
	if got := SupportedProfiles(); len(got) != 3 || got[0] != ProfileStrict || got[1] != ProfileTeam || got[2] != ProfileResearch {
		t.Fatalf("SupportedProfiles() = %+v", got)
	}
	if got := SupportedProfilesCSV(); got != "strict|team|research" {
		t.Fatalf("SupportedProfilesCSV() = %q", got)
	}
}

func TestProfileDefaultRejectSeverities(t *testing.T) {
	strictSet := ProfileStrict.DefaultRejectSeverities()
	if _, ok := strictSet["high"]; !ok {
		t.Fatal("strict set should include high")
	}
	if _, ok := strictSet["critical"]; !ok {
		t.Fatal("strict set should include critical")
	}
	researchSet := ProfileResearch.DefaultRejectSeverities()
	if _, ok := researchSet["high"]; ok {
		t.Fatal("research set should not include high")
	}
	if _, ok := researchSet["critical"]; !ok {
		t.Fatal("research set should include critical")
	}
}

func TestEffectiveRejectSeverities(t *testing.T) {
	t.Run("uses defaults without policy", func(t *testing.T) {
		set, err := EffectiveRejectSeverities(ProfileStrict, false, Config{})
		if err != nil {
			t.Fatalf("EffectiveRejectSeverities() error = %v", err)
		}
		if _, ok := set["critical"]; !ok {
			t.Fatal("default strict set must include critical")
		}
		if _, ok := set["high"]; !ok {
			t.Fatal("default strict set must include high")
		}
	})

	t.Run("allows policy override including medium", func(t *testing.T) {
		set, err := EffectiveRejectSeverities(ProfileTeam, true, Config{
			Profiles: map[string]ProfileConfig{
				"team": {RejectSeverities: []string{"critical", "medium"}},
			},
		})
		if err != nil {
			t.Fatalf("EffectiveRejectSeverities() error = %v", err)
		}
		if _, ok := set["medium"]; !ok {
			t.Fatal("policy override set must include medium")
		}
		if _, ok := set["high"]; ok {
			t.Fatal("policy override set should not include high when omitted")
		}
	})

	t.Run("uses defaults when policy has other profile only", func(t *testing.T) {
		set, err := EffectiveRejectSeverities(ProfileResearch, true, Config{
			Profiles: map[string]ProfileConfig{
				"team": {RejectSeverities: []string{"critical", "medium"}},
			},
		})
		if err != nil {
			t.Fatalf("EffectiveRejectSeverities() error = %v", err)
		}
		if _, ok := set["critical"]; !ok {
			t.Fatal("default research set must include critical")
		}
		if _, ok := set["high"]; ok {
			t.Fatal("default research set should not include high")
		}
	})

	t.Run("rejects profile override missing critical", func(t *testing.T) {
		_, err := EffectiveRejectSeverities(ProfileResearch, true, Config{
			Profiles: map[string]ProfileConfig{
				"research": {RejectSeverities: []string{"high"}},
			},
		})
		if err == nil {
			t.Fatal("expected error for missing critical")
		}
	})

	t.Run("rejects empty and invalid override severities", func(t *testing.T) {
		if _, err := EffectiveRejectSeverities(ProfileStrict, true, Config{
			Profiles: map[string]ProfileConfig{"strict": {}},
		}); err == nil {
			t.Fatal("expected empty reject_severities error")
		}
		if _, err := EffectiveRejectSeverities(ProfileStrict, true, Config{
			Profiles: map[string]ProfileConfig{"strict": {RejectSeverities: []string{"critical", "warn"}}},
		}); err == nil {
			t.Fatal("expected invalid reject severity error")
		}
	})
}
