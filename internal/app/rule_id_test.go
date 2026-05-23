package app

import (
	"regexp"
	"testing"
	"testing/quick"
)

func TestInferRuleIDFromMessage(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "extracts uppercase underscore prefix",
			message: "ARCHIVE_PATH_ESCAPE: archive entry escaped source root",
			want:    "ARCHIVE_PATH_ESCAPE",
		},
		{
			name:    "trims leading and trailing whitespace",
			message: "  DESCRIPTION_TOOL_INJECTION: description contains suspicious instruction  ",
			want:    "DESCRIPTION_TOOL_INJECTION",
		},
		{
			name:    "accepts digits after first character",
			message: "RULE_2026: detected in runtime check",
			want:    "RULE_2026",
		},
		{
			name:    "rejects lowercase prefix",
			message: "archive_path_escape: archive entry escaped source root",
			want:    "",
		},
		{
			name:    "rejects missing colon delimiter",
			message: "ARCHIVE_PATH_ESCAPE archive entry escaped source root",
			want:    "",
		},
		{
			name:    "rejects non-leading occurrence",
			message: "error occurred: ARCHIVE_PATH_ESCAPE: archive entry escaped source root",
			want:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := inferRuleIDFromMessage(tc.message)
			if got != tc.want {
				t.Fatalf("inferRuleIDFromMessage(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}

func TestInferRuleIDFromMessageProperty(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	prop := func(message string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		got := inferRuleIDFromMessage(message)
		if got == "" {
			return true
		}
		return pattern.MatchString(got)
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("inferRuleIDFromMessage property failed: %v", err)
	}
}
