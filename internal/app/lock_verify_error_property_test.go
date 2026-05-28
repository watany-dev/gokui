package app

import (
	"encoding/json"
	"errors"
	"fmt"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
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
			err := errors.New(prefix + middle + suffix)
			if includeDigest {
				err = fmt.Errorf("digest wrapper: %w: %w", errDigestBuildFailed, err)
			}
			if includeInvalid {
				err = fmt.Errorf("invalid wrapper: %w: %w", errLockfileInvalidJSON, err)
			}
			if includeRead {
				err = fmt.Errorf("read wrapper: %w: %w", errLockfileReadFailed, err)
			}

			got := classifyLockVerifyError(err)
			switch {
			case includeRead:
				return got == lockVerifyErrorCodeReadLockfile
			case includeInvalid:
				return got == lockVerifyErrorCodeInvalidLockfile
			case includeDigest:
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
			report.RuleID = rulepkg.InferIDForJSONError(report.Message)
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
