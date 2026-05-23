package app

import "testing"

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
