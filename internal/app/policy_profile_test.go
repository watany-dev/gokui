package app

import "testing"

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

func TestShouldRejectSeverityForProfile(t *testing.T) {
	if !shouldRejectSeverityForProfile(policyProfileStrict, "high") {
		t.Fatal("strict should reject high")
	}
	if !shouldRejectSeverityForProfile(policyProfileTeam, "critical") {
		t.Fatal("team should reject critical")
	}
	if shouldRejectSeverityForProfile(policyProfileResearch, "high") {
		t.Fatal("research should not reject high")
	}
	if !shouldRejectSeverityForProfile(policyProfileResearch, "critical") {
		t.Fatal("research should reject critical")
	}
}
