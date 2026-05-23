package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/quick"
)

func TestClassifyLockVerifyErrorProperties(t *testing.T) {
	t.Run("returns only known error codes", func(t *testing.T) {
		allowed := map[string]struct{}{
			lockVerifyErrorCodeReadLockfile:    {},
			lockVerifyErrorCodeInvalidLockfile: {},
			lockVerifyErrorCodeDigestFailed:    {},
			lockVerifyErrorCodeUnknown:         {},
		}
		prop := func(msg string) bool {
			got := classifyLockVerifyError(errors.New(msg))
			_, ok := allowed[got]
			return ok
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("classifyLockVerifyError code-set property failed: %v", err)
		}
	})

	t.Run("classification precedence is stable", func(t *testing.T) {
		prop := func(prefix string, middle string, suffix string, includeRead bool, includeInvalid bool, includeDigest bool) bool {
			message := prefix
			if includeInvalid {
				message += " invalid lockfile JSON "
			}
			message += middle
			if includeDigest {
				message += " failed to digest installed files "
			}
			message += suffix
			if includeRead {
				message += " failed to read lockfile "
			}

			got := classifyLockVerifyError(errors.New(message))
			switch {
			case strings.Contains(message, "failed to read lockfile"):
				return got == lockVerifyErrorCodeReadLockfile
			case strings.Contains(message, "invalid lockfile JSON"):
				return got == lockVerifyErrorCodeInvalidLockfile
			case strings.Contains(message, "failed to digest installed files"):
				return got == lockVerifyErrorCodeDigestFailed
			default:
				return got == lockVerifyErrorCodeUnknown
			}
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("classifyLockVerifyError precedence property failed: %v", err)
		}
	})
}

func TestLockVerifyJSONErrorEnvelopeProperties(t *testing.T) {
	prop := func(message string, explicitRuleRaw string, useExplicit bool) bool {
		report := lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			Status:        "ERROR",
			ErrorCode:     classifyLockVerifyError(errors.New(message)),
			Message:       message,
			Note:          "property test",
		}
		if useExplicit {
			if explicitRuleRaw == "" {
				report.RuleID = "EXPLICIT_RULE"
			} else {
				report.RuleID = explicitRuleRaw
			}
		} else {
			report.RuleID = inferRuleIDForJSONError(report.Message)
		}

		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return false
		}

		var decoded lockVerifyErrorReport
		if err := json.Unmarshal(out, &decoded); err != nil {
			return false
		}
		if decoded.RuleID != report.RuleID {
			return false
		}

		var top map[string]json.RawMessage
		if err := json.Unmarshal(out, &top); err != nil {
			return false
		}
		_, hasRuleID := top["rule_id"]
		return hasRuleID == (report.RuleID != "")
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("lock verify json error envelope property failed: %v", err)
	}
}
