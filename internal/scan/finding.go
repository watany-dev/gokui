package scan

import (
	"fmt"

	"github.com/watany-dev/gokui/internal/rule"
)

func newFinding(r rule.Rule, file string, line int, summary string) Finding {
	if _, ok := rule.Lookup(r.ID); !ok {
		panic("unregistered scan rule: " + r.ID)
	}
	return Finding{
		ID:       r.ID,
		Severity: string(r.Severity),
		File:     file,
		Line:     line,
		Summary:  summary,
	}
}

func deduplicateFindings(in []Finding) []Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]Finding, 0, len(in))
	for _, finding := range in {
		key := fmt.Sprintf("%s|%s|%d|%s", finding.ID, finding.File, finding.Line, finding.Severity)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

// IsRejectable returns true when finding severity should reject under strict mode.
func IsRejectable(f Finding) bool {
	return f.Severity == "critical" || f.Severity == "high"
}
