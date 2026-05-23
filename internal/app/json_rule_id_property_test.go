package app

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/quick"
)

func TestJSONErrorRuleIDProperties(t *testing.T) {
	t.Run("install writer preserves or infers rule_id", func(t *testing.T) {
		prop := func(message string, explicitRuleRaw string, useExplicit bool) bool {
			var stdout strings.Builder
			var stderr strings.Builder

			rule := ""
			if useExplicit {
				rule = explicitRuleRaw
				if rule == "" {
					rule = "EXPLICIT_RULE"
				}
			}

			report := installErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     installErrorCodeWriteFailed,
				RuleID:        rule,
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

			expectedRule := report.RuleID
			if expectedRule == "" {
				expectedRule = inferRuleIDFromMessage(report.Message)
			}

			var decoded installErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			if decoded.RuleID != expectedRule {
				return false
			}

			var top map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
				return false
			}
			_, hasRuleID := top["rule_id"]
			return hasRuleID == (expectedRule != "")
		}

		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("install rule_id property failed: %v", err)
		}
	})

	t.Run("fetch writer preserves or infers rule_id", func(t *testing.T) {
		prop := func(message string, explicitRuleRaw string, useExplicit bool) bool {
			var stdout strings.Builder
			var stderr strings.Builder

			rule := ""
			if useExplicit {
				rule = explicitRuleRaw
				if rule == "" {
					rule = "EXPLICIT_RULE"
				}
			}

			report := fetchErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     fetchErrorCodeCopyFailed,
				RuleID:        rule,
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

			expectedRule := report.RuleID
			if expectedRule == "" {
				expectedRule = inferRuleIDFromMessage(report.Message)
			}

			var decoded fetchErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			if decoded.RuleID != expectedRule {
				return false
			}

			var top map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
				return false
			}
			_, hasRuleID := top["rule_id"]
			return hasRuleID == (expectedRule != "")
		}

		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("fetch rule_id property failed: %v", err)
		}
	})

	t.Run("update writer preserves or infers rule_id", func(t *testing.T) {
		prop := func(message string, explicitRuleRaw string, useExplicit bool) bool {
			var stdout strings.Builder
			var stderr strings.Builder

			rule := ""
			if useExplicit {
				rule = explicitRuleRaw
				if rule == "" {
					rule = "EXPLICIT_RULE"
				}
			}

			report := updateErrorReport{
				SchemaVersion: reportSchemaVersion,
				Status:        "ERROR",
				ErrorCode:     updateFatalCodeReportBuild,
				RuleID:        rule,
				Message:       message,
				Target:        "/tmp/skills",
				Note:          "property test",
			}
			if code := writeUpdateJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
				return false
			}

			expectedRule := report.RuleID
			if expectedRule == "" {
				expectedRule = inferRuleIDFromMessage(report.Message)
			}

			var decoded updateErrorReport
			if err := json.Unmarshal([]byte(stdout.String()), &decoded); err != nil {
				return false
			}
			if decoded.RuleID != expectedRule {
				return false
			}

			var top map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
				return false
			}
			_, hasRuleID := top["rule_id"]
			return hasRuleID == (expectedRule != "")
		}

		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("update rule_id property failed: %v", err)
		}
	})
}
