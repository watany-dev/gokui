package app

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
)

func writeUpdateSuccessReport(format string, report updateReport, stdout io.Writer) int {
	if format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if format == "sarif" {
		out, _ := json.MarshalIndent(buildUpdateSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildUpdateCompactSummary(report))
	} else {
		_, _ = fmt.Fprintln(stdout, "gokui update report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "target: %s\n", report.Target)
		_, _ = fmt.Fprintf(stdout, "skills: %d\n", report.Summary.Total)
		for _, skill := range report.Skills {
			decision := skill.Decision
			if decision == "" {
				decision = "-"
			}
			_, _ = fmt.Fprintf(stdout, "- %s: %s (decision=%s)\n", skill.Name, skill.Status, decision)
			_, _ = fmt.Fprintf(stdout, "  code: %s\n", skill.ErrorCode)
			_, _ = fmt.Fprintf(stdout, "  diff added=%d removed=%d changed=%d\n", len(skill.Diff.Added), len(skill.Diff.Removed), len(skill.Diff.Changed))
			_, _ = fmt.Fprintf(stdout, "  new urls=%d new executables=%d\n", len(skill.NewURLs), len(skill.NewExecutableFiles))
			_, _ = fmt.Fprintf(stdout, "  severity overrides active=%d added=%d removed=%d\n", len(skill.SeverityOverrides), len(skill.SeverityOverrideDiff.Added), len(skill.SeverityOverrideDiff.Removed))
			_, _ = fmt.Fprintf(stdout, "  note: %s\n", skill.Message)
		}
		_, _ = fmt.Fprintf(stdout, "summary: up_to_date=%d changed=%d rejected=%d skipped=%d errors=%d\n",
			report.Summary.UpToDate,
			report.Summary.Changed,
			report.Summary.Rejected,
			report.Summary.Skipped,
			report.Summary.Errors,
		)
	}

	if report.Summary.Errors > 0 {
		return exitcode.Error.Int()
	}
	if report.Summary.Rejected > 0 {
		return exitcode.Rejected.Int()
	}
	return exitcode.OK.Int()
}
