package app

import (
	"errors"
	formatpkg "github.com/watany-dev/gokui/internal/cli/format"
	policypkg "github.com/watany-dev/gokui/internal/policy"
	"strings"
	"testing"
)

type failingWriteSink struct{}

func (failingWriteSink) Write(_ []byte) (int, error) {
	return 0, errors.New("synthetic write failure")
}

func TestStructuredErrorWritersHandleStdoutWriteFailure(t *testing.T) {
	t.Run("inspect json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInspectJSONError(failingWriteSink{}, &stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     inspectErrorCodeSourceNotFound,
			Message:       "inspect source not found",
			Source:        source{Input: "/tmp/missing", Kind: "local-dir"},
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("inspect json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("inspect sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInspectSARIFError(failingWriteSink{}, &stderr, inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     inspectErrorCodeSourceNotFound,
			Message:       "inspect source not found",
			Source:        source{Input: "/tmp/missing", Kind: "local-dir"},
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("inspect sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("fetch json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeFetchJSONError(failingWriteSink{}, &stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     fetchErrorCodeSourceInvalid,
			Message:       "invalid source",
			Source:        source{Input: "bad", Kind: "github-source"},
			Output:        "/tmp/out",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("fetch json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("fetch sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeFetchSARIFError(failingWriteSink{}, &stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     fetchErrorCodeSourceInvalid,
			Message:       "invalid source",
			Source:        source{Input: "bad", Kind: "github-source"},
			Output:        "/tmp/out",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("fetch sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("install json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInstallJSONError(failingWriteSink{}, &stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       "write failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Target:        "custom:/tmp/skills",
			PolicyProfile: policypkg.ProfileStrict.String(),
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("install json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("install sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeInstallSARIFError(failingWriteSink{}, &stderr, installErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     installErrorCodeWriteFailed,
			Message:       "write failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Target:        "custom:/tmp/skills",
			PolicyProfile: policypkg.ProfileStrict.String(),
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("install sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("update json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeUpdateJSONError(failingWriteSink{}, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "report build failed",
			Target:        "/tmp/skills",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("update json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("update sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeUpdateSARIFError(failingWriteSink{}, &stderr, updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
			ErrorCode:     updateFatalCodeReportBuild,
			Message:       "report build failed",
			Target:        "/tmp/skills",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("update sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("lock verify json", func(t *testing.T) {
		var stderr strings.Builder
		code := writeLockVerifyJSONError(failingWriteSink{}, &stderr, lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			Status:        "ERROR",
			ErrorCode:     lockVerifyErrorCodeUnknown,
			Message:       "lock verify failed",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("lock verify json write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})

	t.Run("lock verify sarif", func(t *testing.T) {
		var stderr strings.Builder
		code := writeLockVerifySARIFError(failingWriteSink{}, &stderr, lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			Status:        "ERROR",
			ErrorCode:     lockVerifyErrorCodeUnknown,
			Message:       "lock verify failed",
			Note:          "test",
		})
		if code != 1 {
			t.Fatalf("lock verify sarif write failure not handled: code=%d stderr=%q", code, stderr.String())
		}
	})
}

func TestStructuredErrorWritersPreserveExplicitRuleID(t *testing.T) {
	const explicitRule = "EXPLICIT_RULE"

	t.Run("inspect json and sarif", func(t *testing.T) {
		report := inspectErrorReport{
			SchemaVersion: reportSchemaVersion,
			ErrorCode:     "",
			RuleID:        explicitRule,
			Message:       "inspect failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Note:          "test",
		}

		var stdout strings.Builder
		var stderr strings.Builder
		if code := writeInspectJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeInspectJSONError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"rule_id": "`+explicitRule+`"`) {
			t.Fatalf("inspect json should preserve explicit rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if code := writeInspectSARIFError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeInspectSARIFError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"ruleId": "`+explicitRule+`"`) {
			t.Fatalf("inspect sarif should preserve explicit ruleId, got %q", stdout.String())
		}
	})

	t.Run("fetch json and sarif", func(t *testing.T) {
		report := fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			ErrorCode:     "",
			RuleID:        explicitRule,
			Message:       "fetch failed",
			Source:        source{Input: "github:org/repo//skills/x@main", Kind: "github-source"},
			Output:        "/tmp/out",
			Note:          "test",
		}

		var stdout strings.Builder
		var stderr strings.Builder
		if code := writeFetchJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeFetchJSONError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"rule_id": "`+explicitRule+`"`) {
			t.Fatalf("fetch json should preserve explicit rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if code := writeFetchSARIFError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeFetchSARIFError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"ruleId": "`+explicitRule+`"`) {
			t.Fatalf("fetch sarif should preserve explicit ruleId, got %q", stdout.String())
		}
	})

	t.Run("install json and sarif", func(t *testing.T) {
		report := installErrorReport{
			SchemaVersion: reportSchemaVersion,
			ErrorCode:     "",
			RuleID:        explicitRule,
			Message:       "install failed",
			Source:        source{Input: "/tmp/skill", Kind: "local-dir"},
			Target:        "custom:/tmp/skills",
			PolicyProfile: policypkg.ProfileStrict.String(),
			Note:          "test",
		}

		var stdout strings.Builder
		var stderr strings.Builder
		if code := writeInstallJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeInstallJSONError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"rule_id": "`+explicitRule+`"`) {
			t.Fatalf("install json should preserve explicit rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if code := writeInstallSARIFError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeInstallSARIFError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"ruleId": "`+explicitRule+`"`) {
			t.Fatalf("install sarif should preserve explicit ruleId, got %q", stdout.String())
		}
	})

	t.Run("update json and sarif", func(t *testing.T) {
		report := updateErrorReport{
			SchemaVersion: reportSchemaVersion,
			ErrorCode:     "",
			RuleID:        explicitRule,
			Message:       "update failed",
			Target:        "/tmp/skills",
			Note:          "test",
		}

		var stdout strings.Builder
		var stderr strings.Builder
		if code := writeUpdateJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeUpdateJSONError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"rule_id": "`+explicitRule+`"`) {
			t.Fatalf("update json should preserve explicit rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if code := writeUpdateSARIFError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeUpdateSARIFError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"ruleId": "`+explicitRule+`"`) {
			t.Fatalf("update sarif should preserve explicit ruleId, got %q", stdout.String())
		}
	})

	t.Run("lock verify json and sarif", func(t *testing.T) {
		report := lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     "/tmp/skill",
			ErrorCode:     "",
			RuleID:        explicitRule,
			Message:       "lock verify failed",
			Note:          "test",
		}

		var stdout strings.Builder
		var stderr strings.Builder
		if code := writeLockVerifyJSONError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeLockVerifyJSONError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"rule_id": "`+explicitRule+`"`) {
			t.Fatalf("lock verify json should preserve explicit rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		if code := writeLockVerifySARIFError(&stdout, &stderr, report); code != 1 || stderr.Len() != 0 {
			t.Fatalf("writeLockVerifySARIFError() code=%d stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), `"ruleId": "`+explicitRule+`"`) {
			t.Fatalf("lock verify sarif should preserve explicit ruleId, got %q", stdout.String())
		}
	})
}

func TestNormalizeStructuredErrorFields(t *testing.T) {
	status, code, ruleID := normalizeStructuredErrorFields("bad-code", "", "wrap: RULE_FROM_MESSAGE: failed", "FALLBACK_CODE")
	if status != "ERROR" {
		t.Fatalf("status = %q, want ERROR", status)
	}
	if code != "FALLBACK_CODE" {
		t.Fatalf("code = %q, want fallback", code)
	}
	if ruleID != "RULE_FROM_MESSAGE" {
		t.Fatalf("ruleID = %q, want inferred rule", ruleID)
	}

	status, code, ruleID = normalizeStructuredErrorFields("KNOWN_CODE", "EXPLICIT_RULE", "OTHER_RULE: ignored", "FALLBACK_CODE")
	if status != "ERROR" || code != "KNOWN_CODE" || ruleID != "EXPLICIT_RULE" {
		t.Fatalf("explicit fields not preserved: status=%q code=%q ruleID=%q", status, code, ruleID)
	}
}

func TestStructuredErrorSARIFProperties(t *testing.T) {
	props := structuredErrorSARIFProperties("v1", "input", "source-kind", "ERROR", "failed", "ERROR_CODE")
	if props.SchemaVersion != "v1" || !props.PreRelease || props.SourceInput != "input" || props.SourceKind != "source-kind" || props.Decision != "ERROR" {
		t.Fatalf("unexpected properties: %+v", props)
	}
	if props.Note != "failed; error_code=ERROR_CODE" {
		t.Fatalf("note = %q, want error code suffix", props.Note)
	}

	props = structuredErrorSARIFPropertiesWithNote("v1", "input", "source-kind", "ERROR", "custom note")
	if props.Note != "custom note" {
		t.Fatalf("custom note = %q, want unchanged", props.Note)
	}
}

func TestEmitStructuredError(t *testing.T) {
	var jsonCalls int
	var sarifCalls int
	writeJSON := func() { jsonCalls++ }
	writeSARIF := func() { sarifCalls++ }

	if !emitStructuredError(formatpkg.JSON, writeJSON, writeSARIF) {
		t.Fatal("json format should be handled")
	}
	if jsonCalls != 1 || sarifCalls != 0 {
		t.Fatalf("json/sarif calls = %d/%d, want 1/0", jsonCalls, sarifCalls)
	}

	if !emitStructuredError(formatpkg.SARIF, writeJSON, writeSARIF) {
		t.Fatal("sarif format should be handled")
	}
	if jsonCalls != 1 || sarifCalls != 1 {
		t.Fatalf("json/sarif calls = %d/%d, want 1/1", jsonCalls, sarifCalls)
	}

	if emitStructuredError(formatpkg.Human, writeJSON, writeSARIF) {
		t.Fatal("human format should not be handled")
	}
	if jsonCalls != 1 || sarifCalls != 1 {
		t.Fatalf("default branch should not call writers, got %d/%d", jsonCalls, sarifCalls)
	}
}

func TestNormalizeCommandDepsDefaults(t *testing.T) {
	vet := normalizeVetDeps(vetDeps{})
	if vet.LoadUserPolicy == nil || vet.LoadRepositoryPolicy == nil || vet.PrepareInspectSource == nil {
		t.Fatal("normalizeVetDeps should fill all defaults")
	}

	inspect := normalizeInspectDeps(inspectDeps{})
	if inspect.PrepareEvaluationSource == nil || inspect.PrepareInspectSource == nil {
		t.Fatal("normalizeInspectDeps should fill all defaults")
	}

	fetch := normalizeFetchDeps(fetchDeps{})
	if fetch.FetchGitHubSkill == nil || fetch.FetchSkillAtomic == nil || fetch.WriteSourceMetadata == nil || fetch.Now == nil {
		t.Fatal("normalizeFetchDeps should fill all defaults")
	}

	install := normalizeInstallDeps(installDeps{})
	if install.LoadUserPolicy == nil || install.LoadRepositoryPolicy == nil || install.PrepareEvaluationSource == nil {
		t.Fatal("normalizeInstallDeps should fill all defaults")
	}

	update := normalizeUpdateDeps(updateDeps{})
	if update.LoadUserPolicy == nil || update.LoadRepositoryPolicy == nil || update.PrepareEvaluationSource == nil {
		t.Fatal("normalizeUpdateDeps should fill all defaults")
	}
}
