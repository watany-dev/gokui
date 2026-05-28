package app

import (
	"encoding/json"
	"errors"
	"fmt"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	"strings"
	"testing"
)

func TestClassifyLockVerifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "wrapped lockfile read failure",
			err:  fmt.Errorf("wrap: %w", errLockfileReadFailed),
			want: lockVerifyErrorCodeReadLockfile,
		},
		{
			name: "wrapped invalid lockfile json",
			err:  fmt.Errorf("wrap: %w", errLockfileInvalidJSON),
			want: lockVerifyErrorCodeInvalidLockfile,
		},
		{
			name: "wrapped digest failure",
			err:  fmt.Errorf("wrap: %w", errDigestBuildFailed),
			want: lockVerifyErrorCodeDigestFailed,
		},
		{
			name: "text-only lockfile phrase does not match",
			err:  errors.New("failed to read lockfile: /x/gokui.lock"),
			want: lockVerifyErrorCodeUnknown,
		},
		{
			name: "other error remains unknown",
			err:  errors.New("other"),
			want: lockVerifyErrorCodeUnknown,
		},
	}
	for _, tc := range cases {
		got := classifyLockVerifyError(tc.err)
		if got != tc.want {
			t.Fatalf("%s: classifyLockVerifyError(%v) = %q, want %q", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestBuildLockVerifySARIFErrorReport(t *testing.T) {
	report := lockVerifyErrorReport{
		SchemaVersion: reportSchemaVersion,
		SkillPath:     "/tmp/skills/demo",
		Status:        "ERROR",
		ErrorCode:     lockVerifyErrorCodeReadLockfile,
		Message:       "failed to read lockfile: /tmp/skills/demo/gokui.lock",
		Note:          "lock verify failed before producing drift report",
	}
	sarif := buildLockVerifySARIFErrorReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	if run.Results[0].RuleID != lockVerifyErrorCodeReadLockfile {
		t.Fatalf("rule id = %q, want %q", run.Results[0].RuleID, lockVerifyErrorCodeReadLockfile)
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("level = %q, want error", run.Results[0].Level)
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocation should be unsuccessful, got %+v", run.Invocations)
	}
	if run.Properties.SourceKind != "installed-skill" {
		t.Fatalf("source kind = %q, want installed-skill", run.Properties.SourceKind)
	}
}

func TestWriteLockVerifySARIFErrorPreservesExplicitRuleID(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder
	code := writeLockVerifySARIFError(&stdout, &stderr, lockVerifyErrorReport{
		SchemaVersion: reportSchemaVersion,
		SkillPath:     "/tmp/skills/demo",
		Status:        "ERROR",
		ErrorCode:     lockVerifyErrorCodeReadLockfile,
		RuleID:        "EXPLICIT_RULE",
		Message:       "EXPLICIT_RULE: synthetic lock verify error",
		Note:          "test",
	})
	if code != 1 {
		t.Fatalf("writeLockVerifySARIFError() code = %d, want 1", code)
	}
	var sarif reportpkg.SARIFDocument
	if err := json.Unmarshal([]byte(stdout.String()), &sarif); err != nil {
		t.Fatalf("sarif parse failed: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif structure: %+v", sarif)
	}
	if sarif.Runs[0].Results[0].RuleID != "EXPLICIT_RULE" {
		t.Fatalf("rule id = %q, want EXPLICIT_RULE", sarif.Runs[0].Results[0].RuleID)
	}
}
