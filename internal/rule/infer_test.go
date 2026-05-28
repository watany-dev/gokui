package rule

import (
	"regexp"
	"testing"
	"testing/quick"
)

func TestInferIDFromMessage(t *testing.T) {
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
			got := InferIDFromMessage(tc.message)
			if got != tc.want {
				t.Fatalf("InferIDFromMessage(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}

func TestInferIDFromMessageProperty(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	prop := func(message string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		got := InferIDFromMessage(message)
		if got == "" {
			return true
		}
		return pattern.MatchString(got)
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("InferIDFromMessage property failed: %v", err)
	}
}

func TestInferIDForJSONError(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "uses leading rule id when present",
			message: "LOCKFILE_TOO_LARGE: failed to read lockfile",
			want:    "LOCKFILE_TOO_LARGE",
		},
		{
			name:    "extracts wrapped rule id from middle of message",
			message: "failed walking skill files for scan: SPECIAL_FILE_IN_SCAN_SOURCE: scan source contains non-regular file: pipe.fifo",
			want:    "SPECIAL_FILE_IN_SCAN_SOURCE",
		},
		{
			name:    "ignores uppercase token without underscore",
			message: "error occurred: ERROR: something failed",
			want:    "",
		},
		{
			name:    "returns empty when no marker exists",
			message: "failed to render update report",
			want:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := InferIDForJSONError(tc.message)
			if got != tc.want {
				t.Fatalf("InferIDForJSONError(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}

func TestInferIDForJSONErrorProperty(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	prop := func(message string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		got := InferIDForJSONError(message)
		if got == "" {
			return true
		}
		return pattern.MatchString(got)
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("InferIDForJSONError property failed: %v", err)
	}
}
