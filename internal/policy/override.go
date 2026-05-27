package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

var severityOverrideRuleIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// SeverityOverrideAudit records explicit policy severity adjustments.
type SeverityOverrideAudit struct {
	RuleID            string `json:"rule_id"`
	PreviousSeverity  string `json:"previous_severity"`
	EffectiveSeverity string `json:"effective_severity"`
	Justification     string `json:"justification"`
	ApprovedBy        string `json:"approved_by"`
	Source            string `json:"source"`
	AppliedAt         string `json:"applied_at"`
}

// SeverityOverrideAuditSet provides stable operations for audit slices.
type SeverityOverrideAuditSet []SeverityOverrideAudit

func (s SeverityOverrideAuditSet) Clone() SeverityOverrideAuditSet {
	if len(s) == 0 {
		return SeverityOverrideAuditSet{}
	}
	out := make(SeverityOverrideAuditSet, len(s))
	copy(out, s)
	return out
}

func (s SeverityOverrideAuditSet) Equal(other SeverityOverrideAuditSet) bool {
	if len(s) != len(other) {
		return false
	}
	for i := range s {
		if s[i] != other[i] {
			return false
		}
	}
	return true
}

func (s SeverityOverrideAuditSet) Sorted() SeverityOverrideAuditSet {
	out := s.Clone()
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].AppliedAt != out[j].AppliedAt {
			return out[i].AppliedAt < out[j].AppliedAt
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func (s SeverityOverrideAuditSet) SortedRuleIDs() []string {
	keys := make([]string, 0, len(s))
	for _, override := range s {
		keys = append(keys, override.RuleID)
	}
	sort.Strings(keys)
	return keys
}

func (s SeverityOverrideAuditSet) Validate() error {
	seenRuleIDs := make(map[string]struct{}, len(s))
	for idx, override := range s {
		if err := validateAuditText(idx, "rule_id", override.RuleID, true); err != nil {
			return err
		}
		ruleID := strings.TrimSpace(override.RuleID)
		if !severityOverrideRuleIDPattern.MatchString(ruleID) {
			return fmt.Errorf("entry %d: rule_id must be canonical uppercase snake case", idx)
		}
		if _, exists := seenRuleIDs[ruleID]; exists {
			return fmt.Errorf("entry %d: duplicate rule_id is not allowed: %s", idx, ruleID)
		}
		seenRuleIDs[ruleID] = struct{}{}
		if err := validateAuditSeverity(idx, "previous_severity", override.PreviousSeverity); err != nil {
			return err
		}
		if err := validateAuditSeverity(idx, "effective_severity", override.EffectiveSeverity); err != nil {
			return err
		}
		if err := validateAuditText(idx, "justification", override.Justification, true); err != nil {
			return err
		}
		if err := validateAuditText(idx, "approved_by", override.ApprovedBy, true); err != nil {
			return err
		}
		if err := validateAuditText(idx, "source", override.Source, true); err != nil {
			return err
		}
		source := strings.TrimSpace(override.Source)
		if source != strings.ToLower(source) {
			return fmt.Errorf("entry %d: source must be canonical lowercase", idx)
		}
		if !isAllowedSeverityOverrideSource(source) {
			return fmt.Errorf("entry %d: source must be an allowed origin (cli-override|policy-file)", idx)
		}
		if err := validateAuditText(idx, "applied_at", override.AppliedAt, true); err != nil {
			return err
		}
		if _, err := time.Parse(time.RFC3339, override.AppliedAt); err != nil {
			return fmt.Errorf("entry %d: applied_at must be RFC3339", idx)
		}
	}
	return nil
}

func AuditValues(in map[string]SeverityOverrideAudit) SeverityOverrideAuditSet {
	out := make(SeverityOverrideAuditSet, 0, len(in))
	for _, override := range in {
		out = append(out, override)
	}
	return out
}

func SortedAuditMapKeys(in map[string]SeverityOverrideAudit) []string {
	keys := make([]string, 0, len(in))
	for ruleID := range in {
		keys = append(keys, ruleID)
	}
	sort.Strings(keys)
	return keys
}

func validateAuditSeverity(idx int, field string, value string) error {
	if err := validateAuditText(idx, field, value, true); err != nil {
		return err
	}
	if !isCanonicalSeverity(value) {
		return fmt.Errorf("entry %d: %s must be canonical severity (critical|high|medium|low)", idx, field)
	}
	return nil
}

func validateAuditText(idx int, field string, value string, required bool) error {
	if strings.IndexFunc(value, isC0OrC1ControlRune) >= 0 {
		return fmt.Errorf("entry %d: %s must not contain C0/C1 control characters", idx, field)
	}
	if containsSeverityOverrideDisallowedUnicode(value) {
		return fmt.Errorf("entry %d: %s must not contain Unicode bidi, zero-width, tag, or variation-selector characters", idx, field)
	}
	trimmed := strings.TrimSpace(value)
	if required && trimmed == "" {
		return fmt.Errorf("entry %d: %s is empty", idx, field)
	}
	if trimmed != value {
		return fmt.Errorf("entry %d: %s must not contain leading or trailing whitespace", idx, field)
	}
	return nil
}

func isCanonicalSeverity(in string) bool {
	switch in {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func isAllowedSeverityOverrideSource(in string) bool {
	switch in {
	case "cli-override", "policy-file":
		return true
	default:
		return false
	}
}

func isC0OrC1ControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1f) || (r >= 0x7f && r <= 0x9f)
}

func containsSeverityOverrideDisallowedUnicode(in string) bool {
	for _, r := range in {
		switch {
		case r >= 0x202a && r <= 0x202e:
			return true
		case r >= 0x2066 && r <= 0x2069:
			return true
		case r == 0x200b, r == 0x200c, r == 0x200d, r == 0x2060, r == 0xfeff:
			return true
		case r >= 0xfe00 && r <= 0xfe0f:
			return true
		case r >= 0xe0100 && r <= 0xe01ef:
			return true
		case r >= 0xe0000 && r <= 0xe007f:
			return true
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return true
		}
	}
	return false
}
