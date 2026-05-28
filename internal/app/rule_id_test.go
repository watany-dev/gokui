package app

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"testing/quick"
)

func TestInferRuleIDForJSONError(t *testing.T) {
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
			got := inferRuleIDForJSONError(tc.message)
			if got != tc.want {
				t.Fatalf("inferRuleIDForJSONError(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}

func TestInferRuleIDForJSONErrorProperty(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)
	prop := func(message string) (ok bool) {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		got := inferRuleIDForJSONError(message)
		if got == "" {
			return true
		}
		return pattern.MatchString(got)
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("inferRuleIDForJSONError property failed: %v", err)
	}
}

func TestWriteInspectJSONErrorInfersWrappedRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeInspectJSONError(&stdout, &stderr, inspectErrorReport{
		SchemaVersion: reportSchemaVersion,
		Status:        "ERROR",
		ErrorCode:     inspectErrorCodeScanFailed,
		Message:       "failed walking skill files for scan: SPECIAL_FILE_IN_SCAN_SOURCE: scan source contains non-regular file: pipe.fifo",
		Source: source{
			Input: "/tmp/skill",
			Kind:  "local-dir",
		},
		Note: "test",
	})
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("writeInspectJSONError() returned code=%d stderr=%q", code, stderr.String())
	}

	var decoded inspectErrorReport
	if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
		t.Fatalf("unmarshal inspect error json: %v", err)
	}
	if decoded.RuleID != "SPECIAL_FILE_IN_SCAN_SOURCE" {
		t.Fatalf("rule_id = %q, want %q", decoded.RuleID, "SPECIAL_FILE_IN_SCAN_SOURCE")
	}
}
