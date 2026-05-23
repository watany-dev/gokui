package app

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"testing/quick"
)

func TestJSONErrorWritersNormalizeStatusProperty(t *testing.T) {
	t.Run("inspect writer normalizes status to ERROR", func(t *testing.T) {
		prop := func(status string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := inspectErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        status,
				ErrorCode:     inspectErrorCodeScanFailed,
				Message:       message,
				Source: source{
					Input: "/tmp/skill",
					Kind:  "local-dir",
				},
				Note: "property test",
			}
			if code := writeInspectJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded inspectErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.Status == "ERROR"
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("inspect status normalization property failed: %v", err)
		}
	})

	t.Run("install writer normalizes status to ERROR", func(t *testing.T) {
		prop := func(status string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        status,
				ErrorCode:     installErrorCodeWriteFailed,
				Message:       message,
				Source: source{
					Input: "/tmp/src",
					Kind:  "local-dir",
				},
				Target:        "custom:/tmp/skills",
				PolicyProfile: "strict",
				Note:          "property test",
			}
			if code := writeInstallJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded installErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.Status == "ERROR"
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("install status normalization property failed: %v", err)
		}
	})

	t.Run("fetch writer normalizes status to ERROR", func(t *testing.T) {
		prop := func(status string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := fetchErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        status,
				ErrorCode:     fetchErrorCodeCopyFailed,
				Message:       message,
				Source: source{
					Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
					Kind:  "github-source",
				},
				Output: "/tmp/out",
				Note:   "property test",
			}
			if code := writeFetchJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded fetchErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.Status == "ERROR"
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("fetch status normalization property failed: %v", err)
		}
	})

	t.Run("update writer normalizes status to ERROR", func(t *testing.T) {
		prop := func(status string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        status,
				ErrorCode:     updateFatalCodeReportBuild,
				Message:       message,
				Target:        "/tmp/skills",
				Note:          "property test",
			}
			if code := writeUpdateJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded updateErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.Status == "ERROR"
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("update status normalization property failed: %v", err)
		}
	})
}

func TestJSONErrorWritersNormalizeErrorCodeProperty(t *testing.T) {
	validPattern := regexp.MustCompile(`^[A-Z0-9_]+$`)

	t.Run("inspect writer normalizes invalid error code to fallback", func(t *testing.T) {
		prop := func(code string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := inspectErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ANY",
				ErrorCode:     code,
				Message:       message,
				Source: source{
					Input: "/tmp/skill",
					Kind:  "local-dir",
				},
				Note: "property test",
			}
			if ret := writeInspectJSONError(&stdout, &stderr, report); ret != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded inspectErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.ErrorCode != "" && validPattern.MatchString(decoded.ErrorCode)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("inspect error_code normalization property failed: %v", err)
		}
	})

	t.Run("fetch writer normalizes invalid error code to fallback", func(t *testing.T) {
		prop := func(code string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := fetchErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ANY",
				ErrorCode:     code,
				Message:       message,
				Source: source{
					Input: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
					Kind:  "github-source",
				},
				Output: "/tmp/out",
				Note:   "property test",
			}
			if ret := writeFetchJSONError(&stdout, &stderr, report); ret != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded fetchErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.ErrorCode != "" && validPattern.MatchString(decoded.ErrorCode)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("fetch error_code normalization property failed: %v", err)
		}
	})

	t.Run("install writer normalizes invalid error code to fallback", func(t *testing.T) {
		prop := func(code string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ANY",
				ErrorCode:     code,
				Message:       message,
				Source: source{
					Input: "/tmp/src",
					Kind:  "local-dir",
				},
				Target:        "custom:/tmp/skills",
				PolicyProfile: "strict",
				Note:          "property test",
			}
			if ret := writeInstallJSONError(&stdout, &stderr, report); ret != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded installErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.ErrorCode != "" && validPattern.MatchString(decoded.ErrorCode)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("install error_code normalization property failed: %v", err)
		}
	})

	t.Run("update writer normalizes invalid error code to fallback", func(t *testing.T) {
		prop := func(code string, message string) bool {
			var stdout strings.Builder
			var stderr strings.Builder
			report := updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ANY",
				ErrorCode:     code,
				Message:       message,
				Target:        "/tmp/skills",
				Note:          "property test",
			}
			if ret := writeUpdateJSONError(&stdout, &stderr, report); ret != 1 || stderr.Len() != 0 {
				return false
			}
			var decoded updateErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			return decoded.ErrorCode != "" && validPattern.MatchString(decoded.ErrorCode)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("update error_code normalization property failed: %v", err)
		}
	})
}
