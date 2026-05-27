package policy

import (
	"strings"
	"testing"
)

func validSeverityOverrideAudit() SeverityOverrideAudit {
	return SeverityOverrideAudit{
		RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
		PreviousSeverity:  "high",
		EffectiveSeverity: "medium",
		Justification:     "approved for controlled fixture",
		ApprovedBy:        "security-reviewer",
		Source:            "policy-file",
		AppliedAt:         "2026-05-24T00:00:00Z",
	}
}

func TestSeverityOverrideAuditSetOperations(t *testing.T) {
	first := validSeverityOverrideAudit()
	second := validSeverityOverrideAudit()
	second.RuleID = "CURL_PIPE_SHELL"
	second.AppliedAt = "2026-05-24T01:00:00Z"

	if clone := SeverityOverrideAuditSet(nil).Clone(); len(clone) != 0 {
		t.Fatalf("nil clone length = %d, want 0", len(clone))
	}

	set := SeverityOverrideAuditSet{first, second}
	clone := set.Clone()
	if !set.Equal(clone) {
		t.Fatal("clone should equal original set")
	}
	clone[0].EffectiveSeverity = "low"
	if set.Equal(clone) {
		t.Fatal("mutated clone should not equal original set")
	}
	if SeverityOverrideAuditSet(nil).Equal(set) {
		t.Fatal("nil set should not equal non-empty set")
	}

	sorted := SeverityOverrideAuditSet{first, second}.Sorted()
	if sorted[0].RuleID != "CURL_PIPE_SHELL" || sorted[1].RuleID != "PROMPT_OVERRIDE_LANGUAGE" {
		t.Fatalf("sorted order mismatch: %+v", sorted)
	}
	sourceTie := validSeverityOverrideAudit()
	sourceTie.Source = "cli-override"
	appliedAtTie := validSeverityOverrideAudit()
	appliedAtTie.AppliedAt = "2026-05-23T00:00:00Z"
	tieSorted := SeverityOverrideAuditSet{first, sourceTie, appliedAtTie}.Sorted()
	if tieSorted[0].AppliedAt != "2026-05-23T00:00:00Z" || tieSorted[1].Source != "cli-override" {
		t.Fatalf("tie-sorted order mismatch: %+v", tieSorted)
	}
	keys := set.SortedRuleIDs()
	if len(keys) != 2 || keys[0] != "CURL_PIPE_SHELL" || keys[1] != "PROMPT_OVERRIDE_LANGUAGE" {
		t.Fatalf("sorted rule IDs mismatch: %+v", keys)
	}
}

func TestSeverityOverrideAuditSetValidate(t *testing.T) {
	valid := SeverityOverrideAuditSet{validSeverityOverrideAudit()}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate(valid) error = %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*SeverityOverrideAudit)
		want   string
	}{
		{
			name:   "empty rule id",
			mutate: func(a *SeverityOverrideAudit) { a.RuleID = "" },
			want:   "rule_id is empty",
		},
		{
			name:   "previous severity with surrounding whitespace",
			mutate: func(a *SeverityOverrideAudit) { a.PreviousSeverity = " high " },
			want:   "previous_severity must not contain leading or trailing whitespace",
		},
		{
			name:   "bad rule id case",
			mutate: func(a *SeverityOverrideAudit) { a.RuleID = "prompt_override_language" },
			want:   "rule_id must be canonical uppercase snake case",
		},
		{
			name:   "bad previous severity",
			mutate: func(a *SeverityOverrideAudit) { a.PreviousSeverity = "HIGH" },
			want:   "previous_severity must be canonical severity",
		},
		{
			name:   "bad effective severity",
			mutate: func(a *SeverityOverrideAudit) { a.EffectiveSeverity = "warn" },
			want:   "effective_severity must be canonical severity",
		},
		{
			name:   "empty justification",
			mutate: func(a *SeverityOverrideAudit) { a.Justification = "" },
			want:   "justification is empty",
		},
		{
			name:   "empty approver",
			mutate: func(a *SeverityOverrideAudit) { a.ApprovedBy = "" },
			want:   "approved_by is empty",
		},
		{
			name:   "bad source case",
			mutate: func(a *SeverityOverrideAudit) { a.Source = "Policy-File" },
			want:   "source must be canonical lowercase",
		},
		{
			name:   "bad source origin",
			mutate: func(a *SeverityOverrideAudit) { a.Source = "manual-edit" },
			want:   "source must be an allowed origin",
		},
		{
			name:   "bad applied at",
			mutate: func(a *SeverityOverrideAudit) { a.AppliedAt = "not-rfc3339" },
			want:   "applied_at must be RFC3339",
		},
		{
			name:   "control character",
			mutate: func(a *SeverityOverrideAudit) { a.ApprovedBy = "reviewer\u007f" },
			want:   "approved_by must not contain C0/C1 control characters",
		},
		{
			name:   "disallowed unicode",
			mutate: func(a *SeverityOverrideAudit) { a.Justification = "approved\u200d" },
			want:   "justification must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name:   "surrounding whitespace",
			mutate: func(a *SeverityOverrideAudit) { a.AppliedAt = " 2026-05-24T00:00:00Z " },
			want:   "applied_at must not contain leading or trailing whitespace",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := validSeverityOverrideAudit()
			tc.mutate(&audit)
			err := SeverityOverrideAuditSet{audit}.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q validation error, got %v", tc.want, err)
			}
		})
	}

	dup := SeverityOverrideAuditSet{validSeverityOverrideAudit(), validSeverityOverrideAudit()}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate rule_id is not allowed") {
		t.Fatalf("expected duplicate rule_id validation error, got %v", err)
	}
}

func TestContainsSeverityOverrideDisallowedUnicode(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{name: "bidi", in: "a\u202eb"},
		{name: "isolate", in: "a\u2066b"},
		{name: "zero width", in: "a\u200bb"},
		{name: "variation selector", in: "a\ufe0fb"},
		{name: "supplement variation selector", in: "a\U000e0100b"},
		{name: "tag", in: "a\U000e0001b"},
		{name: "line separator", in: "a\u2028b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !containsSeverityOverrideDisallowedUnicode(tc.in) {
				t.Fatalf("containsSeverityOverrideDisallowedUnicode(%q) = false, want true", tc.in)
			}
		})
	}
	if containsSeverityOverrideDisallowedUnicode("plain") {
		t.Fatal("plain text should not contain disallowed unicode")
	}
}

func TestAuditMapHelpers(t *testing.T) {
	first := validSeverityOverrideAudit()
	second := validSeverityOverrideAudit()
	second.RuleID = "CURL_PIPE_SHELL"
	in := map[string]SeverityOverrideAudit{
		first.RuleID:  first,
		second.RuleID: second,
	}
	values := AuditValues(in)
	if len(values) != 2 {
		t.Fatalf("AuditValues length = %d, want 2", len(values))
	}
	keys := SortedAuditMapKeys(in)
	if len(keys) != 2 || keys[0] != "CURL_PIPE_SHELL" || keys[1] != "PROMPT_OVERRIDE_LANGUAGE" {
		t.Fatalf("SortedAuditMapKeys mismatch: %+v", keys)
	}
}
