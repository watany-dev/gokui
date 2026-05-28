package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
)

func writeVetSuccessReport(format string, report inspectReport, stdout io.Writer) int {
	switch formatpkg.Format(format) {
	case formatpkg.JSON:
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.ReviewJSON:
		out, _ := json.MarshalIndent(buildInspectReviewReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.SARIF:
		out, _ := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.Compact:
		summary := strings.Replace(buildInspectCompactSummary(report), "inspect ", "vet ", 1)
		_, _ = fmt.Fprintf(stdout, "%s\n", summary)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui vet report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity.String()), finding.ID, finding.File, finding.Line, finding.Summary)
	}
	if report.Decision == reportDecisionRejected {
		return exitcode.Rejected.Int()
	}
	return exitcode.OK.Int()
}
