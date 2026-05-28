package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
)

func writeInspectSuccessReport(format string, report inspectReport, stdout io.Writer, stderr io.Writer) int {
	switch formatpkg.Format(format) {
	case formatpkg.JSON:
		out, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.ReviewJSON:
		out, marshalErr := json.MarshalIndent(buildInspectReviewReport(report), "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect review report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.SARIF:
		out, marshalErr := json.MarshalIndent(buildInspectSARIFReport(report), "", "  ")
		if marshalErr != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render inspect SARIF report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	case formatpkg.Compact:
		_, _ = fmt.Fprintf(stdout, "%s\n", buildInspectCompactSummary(report))
		if report.Decision == reportDecisionRejected {
			return exitcode.Rejected.Int()
		}
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui inspect report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "findings: %d\n", len(report.Findings))
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(stdout, "- [%s] %s %s:%d %s\n", strings.ToUpper(finding.Severity), finding.ID, finding.File, finding.Line, finding.Summary)
	}
	if report.Decision == reportDecisionRejected {
		return exitcode.Rejected.Int()
	}
	return exitcode.OK.Int()
}
