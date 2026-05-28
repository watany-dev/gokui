package app

import (
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
)

func TestContainsSeverityOverrideDisallowedUnicode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain ascii", in: "approved by reviewer", want: false},
		{name: "bidi override", in: "approved\u202E", want: true},
		{name: "bidi isolate", in: "approved\u2067", want: true},
		{name: "zero width joiner", in: "approved\u200D", want: true},
		{name: "variation selector", in: "approved\ufe0f", want: true},
		{name: "variation selector supplement", in: "approved\U000E0100", want: true},
		{name: "unicode tag", in: "approved\U000E0001", want: true},
		{name: "line separator", in: "approved\u2028", want: true},
		{name: "paragraph separator", in: "approved\u2029", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsSeverityOverrideDisallowedUnicode(tc.in); got != tc.want {
				t.Fatalf("containsSeverityOverrideDisallowedUnicode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSeverityOverrideAuditHelpers(t *testing.T) {
	valid := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "medium",
			Justification:     "approved for controlled fixture",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}

	if err := policypkg.SeverityOverrideAuditSet(valid).Validate(); err != nil {
		t.Fatalf("SeverityOverrideAuditSet(valid).Validate() error = %v", err)
	}
	if !policypkg.SeverityOverrideAuditSet(valid).Equal(policypkg.SeverityOverrideAuditSet(valid)) {
		t.Fatal("SeverityOverrideAuditSet(valid).Equal(valid) should be true")
	}
	if policypkg.SeverityOverrideAuditSet(valid).Equal(nil) {
		t.Fatal("SeverityOverrideAuditSet(valid).Equal(nil) should be false")
	}

	t.Run("rejects invalid entries", func(t *testing.T) {
		cases := []struct {
			name       string
			override   severityOverrideAudit
			detailPart string
		}{
			{
				name: "empty rule_id",
				override: severityOverrideAudit{
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id is empty",
			},
			{
				name: "empty previous severity",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity is empty",
			},
			{
				name: "rule_id has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            " PROMPT_OVERRIDE_LANGUAGE ",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain leading or trailing whitespace",
			},
			{
				name: "rule_id has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE\u008f",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "\u0085",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "\u0000",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "\u007f",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "\u007fPROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_\u200dLANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "rule_id must be uppercase snake case",
				override: severityOverrideAudit{
					RuleID:            "prompt_override_language",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must be canonical uppercase snake case",
			},
			{
				name: "previous severity must be canonical",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "HIGH",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must be canonical severity",
			},
			{
				name: "previous severity has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high\u008f",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "\u0085",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "\u0000",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "\u007f",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "\u007fhigh",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high\u200d",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty effective severity",
				override: severityOverrideAudit{
					RuleID:           "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity: "high",
					Justification:    "x",
					ApprovedBy:       "y",
					Source:           "policy-file",
					AppliedAt:        "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity is empty",
			},
			{
				name: "effective severity must be canonical",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "warn",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must be canonical severity",
			},
			{
				name: "effective severity has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "\u0085",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain C0/C1 control characters",
			},
			{
				name: "effective severity has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "\u0000",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain C0/C1 control characters",
			},
			{
				name: "effective severity has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "\u007f",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain C0/C1 control characters",
			},
			{
				name: "effective severity has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "\u007fmedium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain C0/C1 control characters",
			},
			{
				name: "effective severity has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium\u200d",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty justification",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification is empty",
			},
			{
				name: "justification has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "approved\u008f",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "\u0085",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "\u0000",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "\u007f",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "\u007fapproved",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     " approved ",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain leading or trailing whitespace",
			},
			{
				name: "justification has bidi control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "approved\u202E",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty approved_by",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by is empty",
			},
			{
				name: "approved_by has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "reviewer\u008f",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "\u0085",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "\u0000",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "\u007f",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "\u007freviewer",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        " reviewer ",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain leading or trailing whitespace",
			},
			{
				name: "approved_by has zero-width character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "reviewer\u200d",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty source",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source is empty",
			},
			{
				name: "source has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            " policy-file ",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain leading or trailing whitespace",
			},
			{
				name: "source has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file\u008f",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "\u0085",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "\u0000",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "\u007f",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "\u007fpolicy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file\u200d",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "source must be canonical lowercase",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "Policy-File",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must be canonical lowercase",
			},
			{
				name: "source must be allowed origin",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "manual-edit",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must be an allowed origin",
			},
			{
				name: "empty applied_at",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
				},
				detailPart: "applied_at is empty",
			},
			{
				name: "invalid applied_at",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "not-rfc3339",
				},
				detailPart: "applied_at must be RFC3339",
			},
			{
				name: "applied_at has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z\u008f",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has C0/C1 control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "\u0085",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has C0 NUL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "\u0000",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has DEL control character only",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "\u007f",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has DEL control character at edge",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "\u007f2026-05-24T00:00:00Z",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z\u200d",
				},
				detailPart: "applied_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "applied_at has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         " 2026-05-24T00:00:00Z ",
				},
				detailPart: "applied_at must not contain leading or trailing whitespace",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := policypkg.SeverityOverrideAuditSet{tc.override}.Validate()
				if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
					t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
				}
			})
		}
	})

	t.Run("rejects duplicate rule_id entries", func(t *testing.T) {
		dup := []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "approved first",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "low",
				Justification:     "approved duplicate",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T01:00:00Z",
			},
		}
		err := policypkg.SeverityOverrideAuditSet(dup).Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate rule_id is not allowed") {
			t.Fatalf("expected duplicate rule_id validation error, got %v", err)
		}
	})
}

func TestLockFindingSummaryAndSeverityOverrideEqualityBranches(t *testing.T) {
	if err := validateLockFindingSummary(lockFindingSummary{
		Critical: 0,
		High:     1,
		Medium:   2,
		Low:      3,
	}); err != nil {
		t.Fatalf("validateLockFindingSummary(valid) error = %v", err)
	}

	negCases := []struct {
		name    string
		summary lockFindingSummary
		detail  string
	}{
		{
			name:    "critical negative",
			summary: lockFindingSummary{Critical: -1},
			detail:  "critical count",
		},
		{
			name:    "high negative",
			summary: lockFindingSummary{High: -1},
			detail:  "high count",
		},
		{
			name:    "medium negative",
			summary: lockFindingSummary{Medium: -1},
			detail:  "medium count",
		},
		{
			name:    "low negative",
			summary: lockFindingSummary{Low: -1},
			detail:  "low count",
		},
	}
	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLockFindingSummary(tc.summary)
			if err == nil || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("expected %q validation error, got %v", tc.detail, err)
			}
		})
	}

	left := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "medium",
			Justification:     "approved",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}
	right := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "low",
			Justification:     "approved",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}
	if policypkg.SeverityOverrideAuditSet(left).Equal(policypkg.SeverityOverrideAuditSet(right)) {
		t.Fatal("SeverityOverrideAuditSet.Equal should be false for same-length slices with different entries")
	}
}
