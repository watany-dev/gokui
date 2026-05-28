package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestRunFetchOutputFormats(t *testing.T) {
	t.Run("compact output is single-line summary", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "compact-fetch-skill")
		outRoot := t.TempDir()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps([]string{
			"github:org/repo//skills/compact-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"--out", outRoot,
			"--format", "compact",
		}, &stdout, &stderr, fetchDeps{
			FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
				return sourceDir, nil, nil
			},
		})
		if code != 0 {
			t.Fatalf("runFetch(compact) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for compact output, got %q", stderr.String())
		}
		line := strings.TrimSpace(stdout.String())
		if strings.Contains(line, "\n") {
			t.Fatalf("compact output should be single-line, got %q", line)
		}
		for _, marker := range []string{
			"fetch decision=FETCHED",
			"source_kind=github-source",
			"source=\"github:org/repo//skills/compact-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\"",
			"output=",
		} {
			if !strings.Contains(line, marker) {
				t.Fatalf("compact output missing %q: %q", marker, line)
			}
		}
	})

	t.Run("sarif output emits single run with fetched decision", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "sarif-fetch-skill")
		outRoot := t.TempDir()

		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetchWithDeps([]string{
			"github:org/repo//skills/sarif-fetch-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			"--out", outRoot,
			"--format", "sarif",
		}, &stdout, &stderr, fetchDeps{
			FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
				return sourceDir, nil, nil
			},
		})
		if code != 0 {
			t.Fatalf("runFetch(sarif) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif output, got %q", stderr.String())
		}

		var sarif inspectSARIFReport
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("sarif runs = %d, want 1", len(sarif.Runs))
		}
		if sarif.Runs[0].Properties.Decision != "FETCHED" {
			t.Fatalf("sarif decision = %q, want FETCHED", sarif.Runs[0].Properties.Decision)
		}
		if len(sarif.Runs[0].Results) != 0 {
			t.Fatalf("sarif results should be empty for fetch success, got %d", len(sarif.Runs[0].Results))
		}
		if !sarif.Runs[0].Invocations[0].ExecutionSuccessful {
			t.Fatal("sarif invocation executionSuccessful should be true for fetch success")
		}
	})

	t.Run("parse and output-root failures return exit code 1", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder
		code := runFetch(nil, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(parse error) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "fetch source is required") {
			t.Fatalf("stderr should include parse error, got %q", stderr.String())
		}

		sourceDir := createSkillSourceForInstallTest(t, "mkdir-fail-fetch")
		stdout.Reset()
		stderr.Reset()
		outFile := filepath.Join(t.TempDir(), "not-dir")
		if err := os.WriteFile(outFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write out file: %v", err)
		}
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/mkdir-fail-fetch@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", filepath.Join(outFile, "child")},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
			},
		)
		if code != 1 {
			t.Fatalf("runFetch(out mkdir fail) code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "failed to prepare fetch output root") {
			t.Fatalf("stderr should include out mkdir error, got %q", stderr.String())
		}
	})

	t.Run("json mode failures emit machine-readable error report", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := runFetch([]string{"--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(json parse error) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json parse error, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include error status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeArgsInvalid+"\"") {
			t.Fatalf("stdout should include parse error_code, got %q", stdout.String())
		}
		if strings.Contains(stdout.String(), "\"rule_id\":") {
			t.Fatalf("stdout should omit rule_id for non-rule parse errors, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"../../fixtures/clean-skill", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(json unsupported source) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json source error, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+fetchErrorCodeSourceUnsupported+"\"") {
			t.Fatalf("stdout should include source unsupported error_code, got %q", stdout.String())
		}
		if strings.Contains(stdout.String(), "\"rule_id\":") {
			t.Fatalf("stdout should omit rule_id for non-rule source errors, got %q", stdout.String())
		}
	})

	t.Run("sarif mode failures emit machine-readable error report", func(t *testing.T) {
		var stdout strings.Builder
		var stderr strings.Builder

		code := runFetch([]string{"--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif parse error) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif parse error, got %q", stderr.String())
		}

		var sarif inspectSARIFReport
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 {
			t.Fatalf("sarif runs = %d, want 1", len(sarif.Runs))
		}
		run := sarif.Runs[0]
		if run.Properties.Decision != "ERROR" {
			t.Fatalf("decision = %q, want ERROR", run.Properties.Decision)
		}
		if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
			t.Fatalf("invocation executionSuccessful should be false, got %+v", run.Invocations)
		}
		if len(run.Results) != 1 {
			t.Fatalf("sarif results = %d, want 1", len(run.Results))
		}
		if run.Results[0].RuleID != fetchErrorCodeArgsInvalid {
			t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, fetchErrorCodeArgsInvalid)
		}
		if !strings.Contains(run.Properties.Note, "error_code="+fetchErrorCodeArgsInvalid) {
			t.Fatalf("note should include error_code, got %q", run.Properties.Note)
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"../../fixtures/clean-skill", "--out", t.TempDir(), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif unsupported source) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif source error, got %q", stderr.String())
		}
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != fetchErrorCodeSourceUnsupported {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, fetchErrorCodeSourceUnsupported)
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/re\u200bpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif invalid source unicode-threat) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif invalid source error, got %q", stderr.String())
		}
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure for unicode-threat source: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != fetchErrorCodeSourceInvalid {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, fetchErrorCodeSourceInvalid)
		}

		stdout.Reset()
		stderr.Reset()
		code = runFetch([]string{"github:org/repo//skills/x@\u00858f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif invalid source C1-control) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif invalid source error, got %q", stderr.String())
		}
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure for C1-control source: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != fetchErrorCodeSourceInvalid {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, fetchErrorCodeSourceInvalid)
		}
		if !strings.Contains(sarif.Runs[0].Results[0].Message.Text, "must not contain C0/C1 control characters") {
			t.Fatalf("sarif result message should include C0/C1 control-character detail, got %q", sarif.Runs[0].Results[0].Message.Text)
		}

		stdout.Reset()
		stderr.Reset()
		invalidUTF8Source := string([]byte("github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\xff"))
		code = runFetch([]string{invalidUTF8Source, "--out", t.TempDir(), "--format", "sarif"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runFetch(sarif invalid source non-UTF-8) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for sarif invalid source error, got %q", stderr.String())
		}
		if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
			t.Fatalf("sarif parse failed: %v", err)
		}
		if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
			t.Fatalf("unexpected sarif structure for non-UTF-8 source: %+v", sarif)
		}
		if sarif.Runs[0].Results[0].RuleID != fetchErrorCodeSourceInvalid {
			t.Fatalf("rule id = %q, want %q", sarif.Runs[0].Results[0].RuleID, fetchErrorCodeSourceInvalid)
		}
		if !strings.Contains(sarif.Runs[0].Results[0].Message.Text, "must be valid UTF-8") {
			t.Fatalf("sarif result message should include UTF-8 validation detail, got %q", sarif.Runs[0].Results[0].Message.Text)
		}
	})

}
