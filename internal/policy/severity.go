package policy

import (
	"fmt"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type SeveritySet map[Severity]struct{}

func ParseSeverity(in string) (Severity, error) {
	severity := NormalizeSeverity(in)
	if !severity.IsCanonical() {
		return "", fmt.Errorf("invalid severity: %s", severity)
	}
	return severity, nil
}

func NormalizeSeverity(in string) Severity {
	return Severity(strings.ToLower(strings.TrimSpace(in)))
}

func (s Severity) String() string {
	return string(s)
}

func (s Severity) IsCanonical() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

func (s SeveritySet) Strings() map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for severity := range s {
		out[severity.String()] = struct{}{}
	}
	return out
}
