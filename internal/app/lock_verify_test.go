package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/quick"
)

type errorStatter struct {
	err error
}

func (s errorStatter) Stat() (os.FileInfo, error) {
	return nil, s.err
}

func TestParseLockVerifyArgs(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		got, err := parseLockVerifyArgs(nil)
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "." || got.Format != "human" {
			t.Fatalf("unexpected defaults: %+v", got)
		}
	})

	t.Run("path and json format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "json"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "json" {
			t.Fatalf("unexpected parse result: %+v", got)
		}
	})

	t.Run("path and equals-format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format=json"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "json" {
			t.Fatalf("unexpected parse result for equals-format: %+v", got)
		}
	})

	t.Run("path and sarif format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "sarif"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "sarif" {
			t.Fatalf("unexpected parse result for sarif: %+v", got)
		}
	})

	t.Run("path and compact format", func(t *testing.T) {
		got, err := parseLockVerifyArgs([]string{"./skill", "--format", "compact"})
		if err != nil {
			t.Fatalf("parseLockVerifyArgs() error = %v", err)
		}
		if got.Path != "./skill" || got.Format != "compact" {
			t.Fatalf("unexpected parse result for compact: %+v", got)
		}
	})

	t.Run("errors", func(t *testing.T) {
		_, err := parseLockVerifyArgs([]string{"--format"})
		if err == nil || !strings.Contains(err.Error(), "missing value for --format") {
			t.Fatalf("expected format value error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"./a", "./b"})
		if err == nil || !strings.Contains(err.Error(), "at most one path") {
			t.Fatalf("expected too many paths error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--bad"})
		if err == nil || !strings.Contains(err.Error(), "unknown lock verify option") {
			t.Fatalf("expected unknown option error, got %v", err)
		}
		_, err = parseLockVerifyArgs([]string{"--format", "xml"})
		if err == nil || !strings.Contains(err.Error(), "unsupported lock verify format") {
			t.Fatalf("expected unsupported format error, got %v", err)
		}
	})

	t.Run("json-request and path extraction helpers", func(t *testing.T) {
		if !lockVerifyArgsRequestJSON([]string{"--format", "json"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should detect --format json")
		}
		if !lockVerifyArgsRequestJSON([]string{"--format=json"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should detect --format=json")
		}
		if lockVerifyArgsRequestJSON([]string{"--format", "human"}) {
			t.Fatal("lockVerifyArgsRequestJSON() should be false for human format")
		}
		if !lockVerifyArgsRequestSARIF([]string{"--format", "sarif"}) {
			t.Fatal("lockVerifyArgsRequestSARIF() should detect --format sarif")
		}
		if !lockVerifyArgsRequestSARIF([]string{"--format=sarif"}) {
			t.Fatal("lockVerifyArgsRequestSARIF() should detect --format=sarif")
		}
		if lockVerifyArgsRequestSARIF([]string{"--format", "human"}) {
			t.Fatal("lockVerifyArgsRequestSARIF() should be false for human format")
		}

		if got := extractLockVerifyPathArg([]string{"./skill", "--format", "json"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg() = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--format=json", "./skill"}); got != "./skill" {
			t.Fatalf("extractLockVerifyPathArg(equals) = %q, want ./skill", got)
		}
		if got := extractLockVerifyPathArg([]string{"--bad", "--format", "json"}); got != "." {
			t.Fatalf("extractLockVerifyPathArg(default) = %q, want .", got)
		}
	})
}

func TestVerifyLockAndRunLockVerify(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "VERIFIED" {
		t.Fatalf("verify status = %q, want VERIFIED", verifyReport.Status)
	}
	assertCheckCode(t, verifyReport.Checks, "schema", lockVerifyCodeSchema)
	assertCheckCode(t, verifyReport.Checks, "name", lockVerifyCodeName)
	assertCheckCode(t, verifyReport.Checks, "lock_structure", lockVerifyCodeStructure)
	assertCheckCode(t, verifyReport.Checks, "source", lockVerifyCodeSource)
	assertCheckCode(t, verifyReport.Checks, "source_metadata", lockVerifyCodeSourceMetadata)
	assertCheckCode(t, verifyReport.Checks, "install_report", lockVerifyCodeInstallReport)
	assertCheckCode(t, verifyReport.Checks, "file_digests", lockVerifyCodeFileDigests)
	assertCheckCode(t, verifyReport.Checks, "root_hash", lockVerifyCodeRootHash)

	var stdout strings.Builder
	var stderr strings.Builder
	code := runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify() code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "compact"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify(compact verified) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for compact verified output, got %q", stderr.String())
	}
	compactVerified := strings.TrimSpace(stdout.String())
	if strings.Contains(compactVerified, "\n") {
		t.Fatalf("compact output should be single-line, got %q", compactVerified)
	}
	for _, marker := range []string{
		"lock_verify status=VERIFIED",
		"failed=0",
		"missing=0",
		"changed=0",
		"unexpected=0",
	} {
		if !strings.Contains(compactVerified, marker) {
			t.Fatalf("compact verified output missing %q: %q", marker, compactVerified)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "sarif"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify(sarif verified) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif verified output, got %q", stderr.String())
	}
	var verifiedSARIF inspectSARIFReport
	if err := json.Unmarshal([]byte(stdout.String()), &verifiedSARIF); err != nil {
		t.Fatalf("sarif unmarshal (verified): %v", err)
	}
	if len(verifiedSARIF.Runs) != 1 {
		t.Fatalf("verified sarif runs = %d, want 1", len(verifiedSARIF.Runs))
	}
	if verifiedSARIF.Runs[0].Properties.Decision != "PASS" {
		t.Fatalf("verified sarif decision = %q, want PASS", verifiedSARIF.Runs[0].Properties.Decision)
	}
	if len(verifiedSARIF.Runs[0].Results) != 0 {
		t.Fatalf("verified sarif should have no results, got %d", len(verifiedSARIF.Runs[0].Results))
	}
	if !verifiedSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("verified sarif invocation should be executionSuccessful=true")
	}

	if err := os.WriteFile(filepath.Join(installedPath, "README.md"), []byte("changed"), 0o644); err != nil {
		t.Fatalf("mutate installed file: %v", err)
	}
	driftReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock(drift) error = %v", err)
	}
	if driftReport.Status != "DRIFTED" {
		t.Fatalf("drift status = %q, want DRIFTED", driftReport.Status)
	}
	if len(driftReport.Drift.ChangedFiles) == 0 {
		t.Fatalf("expected changed files, got %+v", driftReport.Drift)
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "status: DRIFTED") {
		t.Fatalf("stdout should include drift status, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift json) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "\"status\": \"DRIFTED\"") {
		t.Fatalf("json output should include drift status, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "sarif"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(sarif drifted) code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif drifted output, got %q", stderr.String())
	}
	var driftSARIF inspectSARIFReport
	if err := json.Unmarshal([]byte(stdout.String()), &driftSARIF); err != nil {
		t.Fatalf("sarif unmarshal (drifted): %v", err)
	}
	if len(driftSARIF.Runs) != 1 {
		t.Fatalf("drift sarif runs = %d, want 1", len(driftSARIF.Runs))
	}
	if driftSARIF.Runs[0].Properties.Decision != "DRIFTED" {
		t.Fatalf("drift sarif decision = %q, want DRIFTED", driftSARIF.Runs[0].Properties.Decision)
	}
	if len(driftSARIF.Runs[0].Results) == 0 {
		t.Fatal("drift sarif should include failed-check results")
	}
	if driftSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("drift sarif invocation should be executionSuccessful=false")
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "compact"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(compact drifted) code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for compact drifted output, got %q", stderr.String())
	}
	compactDrift := strings.TrimSpace(stdout.String())
	if strings.Contains(compactDrift, "\n") {
		t.Fatalf("compact output should be single-line, got %q", compactDrift)
	}
	for _, marker := range []string{
		"lock_verify status=DRIFTED",
		"failed=",
		"changed=",
		"path=",
	} {
		if !strings.Contains(compactDrift, marker) {
			t.Fatalf("compact drifted output missing %q: %q", marker, compactDrift)
		}
	}
}

func TestBuildLockVerifySARIFReport(t *testing.T) {
	report := lockVerifyReport{
		SchemaVersion: reportSchemaVersion,
		SkillPath:     "/tmp/skills/demo",
		Status:        "DRIFTED",
		Checks: []lockVerifyCheck{
			{Code: lockVerifyCodeSchema, Name: "schema", OK: true, Detail: "ok"},
			{Code: lockVerifyCodeFileDigests, Name: "file_digests", OK: false, Detail: "missing=1 changed=1 unexpected=1"},
		},
		Drift: lockVerifyDriftInfo{
			MissingFiles:    []string{"missing.md"},
			ChangedFiles:    []string{"changed.md"},
			UnexpectedFiles: []string{"extra.md"},
		},
		Note: "test",
	}

	sarif := buildLockVerifySARIFReport(report)
	if sarif.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if run.Properties.Decision != "DRIFTED" {
		t.Fatalf("decision = %q, want DRIFTED", run.Properties.Decision)
	}
	if run.Properties.SourceKind != "installed-skill" {
		t.Fatalf("source_kind = %q, want installed-skill", run.Properties.SourceKind)
	}
	if run.Invocations[0].ExecutionSuccessful {
		t.Fatal("executionSuccessful should be false for drifted report")
	}
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("expected rules in sarif driver")
	}

	foundSummary := false
	foundMissing := false
	foundChanged := false
	foundUnexpected := false
	for _, result := range run.Results {
		if result.RuleID != lockVerifyCodeFileDigests {
			continue
		}
		switch {
		case strings.Contains(result.Message.Text, "missing=1 changed=1 unexpected=1"):
			foundSummary = true
		case strings.Contains(result.Message.Text, "missing file listed in lock") && strings.Contains(result.Message.Text, "missing.md"):
			foundMissing = true
		case strings.Contains(result.Message.Text, "changed file hash or size") && strings.Contains(result.Message.Text, "changed.md"):
			foundChanged = true
		case strings.Contains(result.Message.Text, "unexpected file not listed in lock") && strings.Contains(result.Message.Text, "extra.md"):
			foundUnexpected = true
		}
	}
	if !foundSummary || !foundMissing || !foundChanged || !foundUnexpected {
		t.Fatalf("missing expected digest drift results: %+v", run.Results)
	}
}

func TestVerifyLockSchemaControlCharactersDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-control-char")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-control-char", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "gokui.lock/v1\u008f"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain C0/C1 control characters")
}

func TestVerifyLockSchemaControlCharactersEdgeDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-control-char-edge")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-control-char-edge", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "\u0085gokui.lock/v1"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain C0/C1 control characters")
}

func TestVerifyLockSchemaWhitespaceDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-whitespace")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-whitespace", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = " gokui.lock/v1 "
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain leading or trailing whitespace")
}

func TestVerifyLockSchemaUnicodeCharactersDetail(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "verify-schema-unicode-char")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-schema-unicode-char", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	lock, err := readInstallLock(lockPath)
	if err != nil {
		t.Fatalf("readInstallLock(valid) error = %v", err)
	}
	lock.Schema = "gokui.lock/v1\u200d"
	raw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	verifyReport, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if verifyReport.Status != "DRIFTED" {
		t.Fatalf("verify status = %q, want DRIFTED", verifyReport.Status)
	}
	assertCheckFailedContains(t, verifyReport.Checks, "schema", "must not contain Unicode bidi, zero-width, tag, or variation-selector characters")
}

func TestBuildLockVerifyCompactSummary(t *testing.T) {
	report := lockVerifyReport{
		SkillPath: "/tmp/skills/demo",
		Status:    "DRIFTED",
		Checks: []lockVerifyCheck{
			{Code: lockVerifyCodeSchema, Name: "schema", OK: true, Detail: "ok"},
			{Code: lockVerifyCodeFileDigests, Name: "file_digests", OK: false, Detail: "missing=1 changed=1 unexpected=1"},
			{Code: lockVerifyCodeRootHash, Name: "root_hash", OK: false, Detail: "hash mismatch"},
		},
		Drift: lockVerifyDriftInfo{
			MissingFiles:    []string{"a.md"},
			ChangedFiles:    []string{"b.md"},
			UnexpectedFiles: []string{"c.md", "d.md"},
		},
	}
	got := buildLockVerifyCompactSummary(report)
	required := []string{
		"lock_verify status=DRIFTED",
		"checks=3",
		"failed=2",
		"missing=1",
		"changed=1",
		"unexpected=2",
		"path=\"/tmp/skills/demo\"",
	}
	for _, marker := range required {
		if !strings.Contains(got, marker) {
			t.Fatalf("compact summary missing marker %q: %q", marker, got)
		}
	}
}

func TestVerifyLockErrorsAndDiff(t *testing.T) {
	_, err := verifyLock(filepath.Join(t.TempDir(), "missing"))
	if err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected missing lockfile error, got %v", err)
	}

	if runtime.GOOS != "windows" {
		t.Run("verify root path is symlink", func(t *testing.T) {
			base := t.TempDir()
			real := filepath.Join(base, "real-skill")
			if err := os.Mkdir(real, 0o755); err != nil {
				t.Fatalf("mkdir real skill: %v", err)
			}
			if err := os.WriteFile(filepath.Join(real, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
				t.Fatalf("write lockfile: %v", err)
			}
			link := filepath.Join(base, "skill-link")
			if err := os.Symlink("real-skill", link); err != nil {
				t.Fatalf("create symlink: %v", err)
			}

			_, err := verifyLock(link)
			if err == nil || !strings.Contains(err.Error(), ruleLockVerifyPathSymlink) {
				t.Fatalf("expected symlinked verify path rejection, got %v", err)
			}
		})
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, installLockFile), []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken lock: %v", err)
	}
	_, err = verifyLock(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid lockfile JSON") {
		t.Fatalf("expected invalid JSON error, got %v", err)
	}

	invalidUTF8Dir := t.TempDir()
	invalidUTF8Lock := append([]byte(`{"schema":"gokui.lock/v1","name":"skill","source":{"type":"local","input":"/tmp/skill","kind":"local-dir"},"skill":{"root_sha256":"abc"},"policy":{"profile":"strict","decision":"pass"},"note":"`), 0xff)
	invalidUTF8Lock = append(invalidUTF8Lock, []byte(`"}`)...)
	if err := os.WriteFile(filepath.Join(invalidUTF8Dir, installLockFile), invalidUTF8Lock, 0o644); err != nil {
		t.Fatalf("write invalid utf-8 lock: %v", err)
	}
	_, err = verifyLock(invalidUTF8Dir)
	if err == nil || !strings.Contains(err.Error(), ruleLockfileInvalidUTF8) || !strings.Contains(err.Error(), "invalid lockfile JSON") {
		t.Fatalf("expected invalid utf-8 lockfile JSON error, got %v", err)
	}

	t.Run("oversized lockfile", func(t *testing.T) {
		origLimit := maxLockVerifyLockFileBytes
		maxLockVerifyLockFileBytes = 8
		t.Cleanup(func() { maxLockVerifyLockFileBytes = origLimit })

		oversizedDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(oversizedDir, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write oversized lockfile: %v", err)
		}
		_, err := verifyLock(oversizedDir)
		if err == nil || !strings.Contains(err.Error(), ruleLockfileTooLarge) || !strings.Contains(err.Error(), "failed to read lockfile") {
			t.Fatalf("expected oversized lockfile read failure, got %v", err)
		}
	})

	t.Run("lockfile path is directory", func(t *testing.T) {
		dirWithLockDir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dirWithLockDir, installLockFile), 0o755); err != nil {
			t.Fatalf("mkdir lock path dir: %v", err)
		}
		_, err := verifyLock(dirWithLockDir)
		if err == nil || !strings.Contains(err.Error(), ruleLockfileSpecialFile) {
			t.Fatalf("expected lockfile special-file error for directory path, got %v", err)
		}
	})

	t.Run("lockfile is unreadable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		dir := t.TempDir()
		lockPath := filepath.Join(dir, installLockFile)
		if err := os.WriteFile(lockPath, []byte(`{"schema":"gokui.lock/v1"}`), 0o600); err != nil {
			t.Fatalf("write lockfile: %v", err)
		}
		if err := os.Chmod(lockPath, 0o000); err != nil {
			t.Fatalf("chmod lockfile: %v", err)
		}
		defer os.Chmod(lockPath, 0o600)

		_, err := verifyLock(dir)
		if err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
			t.Fatalf("expected unreadable lockfile read error, got %v", err)
		}
	})

	missing, changed, unexpected := diffLockFiles(
		[]lockFileHash{
			{Path: "a.txt", SHA256: "1", Bytes: 1},
			{Path: "b.txt", SHA256: "2", Bytes: 2},
		},
		[]lockFileHash{
			{Path: "b.txt", SHA256: "3", Bytes: 2},
			{Path: "c.txt", SHA256: "4", Bytes: 3},
		},
	)
	if len(missing) != 1 || missing[0] != "a.txt" {
		t.Fatalf("unexpected missing: %+v", missing)
	}
	if len(changed) != 1 || changed[0] != "b.txt" {
		t.Fatalf("unexpected changed: %+v", changed)
	}
	if len(unexpected) != 1 || unexpected[0] != "c.txt" {
		t.Fatalf("unexpected unexpected files: %+v", unexpected)
	}
}

func TestLockVerifyStableFileHelpers(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "first.txt")
	if err := os.WriteFile(firstPath, []byte("one"), 0o644); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	secondPath := filepath.Join(root, "second.txt")
	if err := os.WriteFile(secondPath, []byte("two"), 0o644); err != nil {
		t.Fatalf("write second file: %v", err)
	}

	firstInfo, err := os.Lstat(firstPath)
	if err != nil {
		t.Fatalf("lstat first file: %v", err)
	}
	secondInfo, err := os.Lstat(secondPath)
	if err != nil {
		t.Fatalf("lstat second file: %v", err)
	}

	if err := ensureLockfileStableFile(firstInfo, firstInfo, firstPath); err != nil {
		t.Fatalf("same lockfile identity should pass, got %v", err)
	}
	err = ensureLockfileStableFile(firstInfo, secondInfo, secondPath)
	if err == nil || !strings.Contains(err.Error(), ruleLockfileSourceChanged) || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected lockfile source-changed read error, got %v", err)
	}

	if err := ensureInstallReportStableFile(firstInfo, firstInfo, firstPath); err != nil {
		t.Fatalf("same install-report identity should pass, got %v", err)
	}
	err = ensureInstallReportStableFile(firstInfo, secondInfo, secondPath)
	if err == nil || !strings.Contains(err.Error(), ruleInstallReportSourceChanged) {
		t.Fatalf("expected install-report source-changed error, got %v", err)
	}

	if err := ensureLockfileStableFromOpen(firstInfo, errorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to read lockfile") {
		t.Fatalf("expected lockfile stat error, got %v", err)
	}
	if err := ensureInstallReportStableFromOpen(firstInfo, errorStatter{err: errors.New("stat fail")}, firstPath); err == nil || !strings.Contains(err.Error(), "failed to read install report") {
		t.Fatalf("expected install report stat error, got %v", err)
	}

	opened, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open first file: %v", err)
	}
	defer opened.Close()
	if err := ensureLockfileStableFromOpen(firstInfo, opened, firstPath); err != nil {
		t.Fatalf("same opened lockfile should pass, got %v", err)
	}
	if err := ensureInstallReportStableFromOpen(firstInfo, opened, firstPath); err != nil {
		t.Fatalf("same opened install report should pass, got %v", err)
	}
}

func TestRunLockVerifyErrorPathsAndDriftKinds(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runLockVerify([]string{"--format"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse error) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "missing value for --format") {
		t.Fatalf("stderr should include parse error, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{"--bad", "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse json error) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json parse error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
		t.Fatalf("stdout should include error status, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeArgsInvalid+"\"") {
		t.Fatalf("stdout should include args-invalid error_code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"skill_path\": \".\"") {
		t.Fatalf("stdout should include default skill_path for parse error, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{"--bad", "--format", "sarif"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(parse sarif error) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif parse error output, got %q", stderr.String())
	}
	var parseSARIF inspectSARIFReport
	if err := json.Unmarshal([]byte(stdout.String()), &parseSARIF); err != nil {
		t.Fatalf("sarif parse (parse error): %v", err)
	}
	if len(parseSARIF.Runs) != 1 || len(parseSARIF.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif parse-error structure: %+v", parseSARIF)
	}
	if parseSARIF.Runs[0].Results[0].RuleID != lockVerifyErrorCodeArgsInvalid {
		t.Fatalf("parse sarif rule id = %q, want %q", parseSARIF.Runs[0].Results[0].RuleID, lockVerifyErrorCodeArgsInvalid)
	}
	if parseSARIF.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("parse sarif invocation should be executionSuccessful=false")
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill")}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock) code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-compact"), "--format", "compact"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock compact) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty for compact error output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to read lockfile") {
		t.Fatalf("stderr should include missing lockfile error for compact output, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-json"), "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
		t.Fatalf("stdout should include error status, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "\"rule_id\":") {
		t.Fatalf("stdout should omit rule_id when no rule-prefixed error is present, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{filepath.Join(t.TempDir(), "missing-skill-sarif"), "--format", "sarif"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(missing lock sarif) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for sarif error output, got %q", stderr.String())
	}
	var readSARIF inspectSARIFReport
	if err := json.Unmarshal([]byte(stdout.String()), &readSARIF); err != nil {
		t.Fatalf("sarif parse (read error): %v", err)
	}
	if len(readSARIF.Runs) != 1 || len(readSARIF.Runs[0].Results) != 1 {
		t.Fatalf("unexpected sarif read-error structure: %+v", readSARIF)
	}
	if readSARIF.Runs[0].Results[0].RuleID != lockVerifyErrorCodeReadLockfile {
		t.Fatalf("read sarif rule id = %q, want %q", readSARIF.Runs[0].Results[0].RuleID, lockVerifyErrorCodeReadLockfile)
	}
	if readSARIF.Runs[0].Properties.Decision != "ERROR" {
		t.Fatalf("read sarif decision = %q, want ERROR", readSARIF.Runs[0].Properties.Decision)
	}
	if !strings.Contains(readSARIF.Runs[0].Properties.Note, "error_code="+lockVerifyErrorCodeReadLockfile) {
		t.Fatalf("read sarif note should include error_code, got %q", readSARIF.Runs[0].Properties.Note)
	}

	if runtime.GOOS != "windows" {
		stdout.Reset()
		stderr.Reset()
		symlinkPathBase := t.TempDir()
		symlinkPathReal := filepath.Join(symlinkPathBase, "real-skill")
		if err := os.Mkdir(symlinkPathReal, 0o755); err != nil {
			t.Fatalf("mkdir real lock-verify path: %v", err)
		}
		if err := os.WriteFile(filepath.Join(symlinkPathReal, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write lock in real path: %v", err)
		}
		symlinkPath := filepath.Join(symlinkPathBase, "skill-link")
		if err := os.Symlink("real-skill", symlinkPath); err != nil {
			t.Fatalf("create lock-verify path symlink: %v", err)
		}

		code = runLockVerify([]string{symlinkPath}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(path symlink human) code = %d, want 1", code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("stdout should be empty for human error output, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), ruleLockVerifyPathSymlink) {
			t.Fatalf("stderr should include lock-verify path symlink rule, got %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = runLockVerify([]string{symlinkPath, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(path symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"status\": \"ERROR\"") {
			t.Fatalf("stdout should include error status, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockVerifyPathSymlink+"\"") {
			t.Fatalf("stdout should include lock-verify path symlink rule_id, got %q", stdout.String())
		}

		stdout.Reset()
		stderr.Reset()
		symlinkDir := t.TempDir()
		realLock := filepath.Join(symlinkDir, "real.lock")
		if err := os.WriteFile(realLock, []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
			t.Fatalf("write real lock: %v", err)
		}
		if err := os.Symlink("real.lock", filepath.Join(symlinkDir, installLockFile)); err != nil {
			t.Fatalf("create lock symlink: %v", err)
		}
		code = runLockVerify([]string{symlinkDir, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(lockfile symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
			t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileSymlink+"\"") {
			t.Fatalf("stdout should include lockfile symlink rule_id, got %q", stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	origLimit := maxLockVerifyLockFileBytes
	maxLockVerifyLockFileBytes = 8
	oversizedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(oversizedDir, installLockFile), []byte(`{"schema":"gokui.lock/v1"}`), 0o644); err != nil {
		t.Fatalf("write oversized lockfile: %v", err)
	}
	code = runLockVerify([]string{oversizedDir, "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(oversized lock json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileTooLarge+"\"") {
		t.Fatalf("stdout should include lockfile-too-large rule_id, got %q", stdout.String())
	}
	maxLockVerifyLockFileBytes = origLimit

	stdout.Reset()
	stderr.Reset()
	lockDirSkill := t.TempDir()
	if err := os.Mkdir(filepath.Join(lockDirSkill, installLockFile), 0o755); err != nil {
		t.Fatalf("mkdir lockfile directory path: %v", err)
	}
	code = runLockVerify([]string{lockDirSkill, "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(lockfile special-file json) code = %d, want 1", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeReadLockfile+"\"") {
		t.Fatalf("stdout should include read-lockfile error code, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleLockfileSpecialFile+"\"") {
		t.Fatalf("stdout should include lockfile special-file rule_id, got %q", stdout.String())
	}

	if runtime.GOOS != "windows" {
		stdout.Reset()
		stderr.Reset()
		src := createSkillSourceForInstallTest(t, "digest-symlink-skill")
		targetRoot := filepath.Join(t.TempDir(), "skills-digest-symlink")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "digest-symlink-skill", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}
		if err := os.Symlink("README.md", filepath.Join(installedPath, "link.txt")); err != nil {
			t.Fatalf("create symlink in installed skill: %v", err)
		}
		code = runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runLockVerify(digest symlink json) code = %d, want 1", code)
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"error_code\": \""+lockVerifyErrorCodeDigestFailed+"\"") {
			t.Fatalf("stdout should include digest-failed error_code, got %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+ruleInstallDigestSymlink+"\"") {
			t.Fatalf("stdout should include digest symlink rule_id, got %q", stdout.String())
		}
	}

	src := createSkillSourceForInstallTest(t, "drift-kinds-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "drift-kinds-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}
	if err := os.Remove(filepath.Join(installedPath, "README.md")); err != nil {
		t.Fatalf("remove README for missing drift: %v", err)
	}
	if err := os.WriteFile(filepath.Join(installedPath, "extra.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatalf("write extra drift file: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runLockVerify(drift kinds) code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), "missing: README.md") {
		t.Fatalf("stdout should include missing files, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "unexpected: extra.txt") {
		t.Fatalf("stdout should include unexpected files, got %q", stdout.String())
	}
}

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
	var sarif inspectSARIFReport
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

func TestVerifyLockSourceChecks(t *testing.T) {
	lock := installLock{
		Schema: "gokui.lock/v1",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/skill",
			Kind:  "local-dir",
		},
	}
	ok, detail := verifyLockSource(lock)
	if !ok {
		t.Fatalf("expected source check pass, detail=%q", detail)
	}

	lock.Source.Kind = ""
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("empty kind should fail")
	}

	lock.Source.Kind = "local-dir"
	lock.Source.Input = ""
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("empty input should fail")
	}
	lock.Source.Input = " /tmp/skill "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with surrounding whitespace should fail")
	}
	lock.Source.Input = "/tmp/skill\npayload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with C0 control characters should fail")
	}
	lock.Source.Input = "/tmp/skill\u0085payload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with C1 control characters should fail")
	}
	lock.Source.Input = "\u0085/tmp/skill"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with edge C1 control characters should fail")
	}
	lock.Source.Input = "\u0085"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("input with C1 control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("input with C1 control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Input = "/tmp/skill\u200dpayload"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("input with unicode obfuscation characters should fail")
	}
	lock.Source.Input = "/tmp/skill"
	lock.Source.Kind = " local-dir "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with surrounding whitespace should fail")
	}
	lock.Source.Kind = "local\u008fdir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with C0/C1 control characters should fail")
	}
	lock.Source.Kind = "\u0085local-dir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with edge C1 control characters should fail")
	}
	lock.Source.Kind = "\u0085"
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("kind with C0/C1 control characters only should fail")
	} else if !strings.Contains(detail, "must not contain C0/C1 control characters") {
		t.Fatalf("kind with C0/C1 control characters only should surface control detail, got %q", detail)
	}
	lock.Source.Kind = "local-dir\u200d"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with unicode obfuscation characters should fail")
	}
	lock.Source.Kind = "LOCAL-DIR"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind with uppercase letters should fail")
	}
	lock.Source.Kind = "local-dir"
	lock.Source.Type = ""
	if ok, detail := verifyLockSource(lock); ok {
		t.Fatal("empty source type should fail")
	} else if !strings.Contains(detail, "lock source type is empty") {
		t.Fatalf("empty source type should surface empty detail, got %q", detail)
	}
	lock.Source.Type = "local"
	lock.Source.Type = " local "
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with surrounding whitespace should fail")
	}
	lock.Source.Type = "loca\u008fl"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with C0/C1 control characters should fail")
	}
	lock.Source.Type = "\u0085local"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with edge C1 control characters should fail")
	}
	lock.Source.Type = "local\u200d"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with unicode obfuscation characters should fail")
	}
	lock.Source.Type = "LOCAL"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type with uppercase letters should fail")
	}
	lock.Source.Type = "local"
	lock.Source.Input = "/tmp/skill/../skill"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("non-canonical local input path should fail")
	}

	lock.Source.Input = "/tmp/skill"
	lock.Source.Kind = "unsupported"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("unsupported kind should fail")
	}

	lock.Source.Kind = "local-dir"
	lock.Source.Type = "archive"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("type/kind mismatch should fail")
	}

	lock.Source.Type = "local"
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	lock.Source.Kind = "local-dir"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("kind/input mismatch should fail")
	}

	lock.Source.Kind = "github-source"
	lock.Source.Type = "github"
	lock.Source.Input = "github:org/repo/path@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github source syntax should fail")
	}
	lock.Source.Input = "github:owner_name/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("invalid github owner format should fail")
	}
	lock.Source.Input = "github:Owner/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("uppercase github owner should fail")
	}
	lock.Source.Input = "github:owner/Repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("uppercase github repo should fail")
	}
	lock.Source.Input = "github:owner/.repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("leading-dot github repo should fail")
	}
	lock.Source.Input = "github:owner/repo.//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("trailing-dot github repo should fail")
	}
	lock.Source.Input = "github:owner/repo.git//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github repo .git suffix should fail")
	}
	lock.Source.Input = "github:owner/re..po//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github repo consecutive dots should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@shadow@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with @ in path should fail")
	}
	lock.Source.Input = "github:org/repo//skills:demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with : in path should fail")
	}
	lock.Source.Input = "github:org/repo//skills/con@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with reserved device path segment should fail")
	}
	lock.Source.Input = "github:org/repo//skills/COM¹.txt@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with reserved superscript-device path segment should fail")
	}
	lock.Source.Input = "github:org/repo//skills/\u202edemo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path bidi-control should fail")
	}
	lock.Source.Input = "github:org/repo//skills/\u200bdemo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path zero-width char should fail")
	}
	lock.Source.Input = "github:org/repo//skills/my skill@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path whitespace char should fail")
	}
	lock.Source.Input = "github:org/repo//skills/ demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path-segment leading space should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo.@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path-segment trailing dot should fail")
	}
	lock.Source.Input = "github:org/repo//skills/./demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("non-canonical github source input should fail")
	}
	lock.Source.Input = "github:org/repo// skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with path surrounding spaces should fail")
	}
	lock.Source.Input = "github:org/repo//skills//demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with non-canonical path segments should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u00a01234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with unicode-whitespace ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u00851234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with C1 control ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u200b1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with zero-width ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\u202e1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with bidi-control ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\U000E00011234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with unicode-tag ref should fail")
	}
	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f90\ufe0f1234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with variation-selector ref should fail")
	}
	lock.Source.Input = "github:or\u00a0g/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with owner unicode-whitespace should fail")
	}
	lock.Source.Input = "github:org/re\u200bpo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with repo zero-width should fail")
	}
	lock.Source.Input = "github:or\U000E0001g/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with owner unicode tag should fail")
	}
	lock.Source.Input = "github:org/re\ufe0fpo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("github source input with repo variation-selector should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@main"
	if ok, _ := verifyLockSource(lock); ok {
		t.Fatal("floating github ref should fail")
	}

	lock.Source.Input = "github:org/repo//skills/demo@abc1234a4b5c6d7e8f901234567890abcdef1234"
	if ok, detail := verifyLockSource(lock); !ok {
		t.Fatalf("expected github pinned source check pass, detail=%q", detail)
	}
}

func TestVerifyLockSourceMetadataCheck(t *testing.T) {
	t.Run("local sources do not require source metadata", func(t *testing.T) {
		lock := installLock{
			Schema: "gokui.lock/v1",
			Source: lockSource{
				Type:  "local",
				Input: "/tmp/skill",
				Kind:  "local-dir",
			},
		}
		ok, detail := verifyLockSourceMetadata(t.TempDir(), lock)
		if !ok {
			t.Fatalf("expected source metadata check pass for local source: %q", detail)
		}
		if !strings.Contains(detail, "not required") {
			t.Fatalf("unexpected detail: %q", detail)
		}
	})

	t.Run("github sources require source metadata", func(t *testing.T) {
		src := createSkillSourceForInstallTest(t, "verify-source-meta")
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "verify-source-meta", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}

		lockPath := filepath.Join(installedPath, installLockFile)
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		lock.Source = lockSource{
			Type:  "github",
			Input: "github:org/repo//skills/verify-source-meta@abc1234a4b5c6d7e8f901234567890abcdef1234",
			Kind:  "github-source",
		}
		updated, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		ok, detail := verifyLockSourceMetadata(installedPath, lock)
		if ok {
			t.Fatalf("expected source metadata failure without metadata file: %q", detail)
		}
		if !strings.Contains(detail, "missing source metadata") {
			t.Fatalf("expected missing metadata detail, got %q", detail)
		}

		_, installedRootHash, err := buildFileDigestsFiltered(installedPath, map[string]struct{}{
			sourceMetadataFile: {},
			installReportFile:  {},
			installLockFile:    {},
		})
		if err != nil {
			t.Fatalf("buildFileDigestsFiltered() error = %v", err)
		}
		if err := writeSourceMetadata(installedPath, sourceMetadata{
			Schema:          "gokui.source/v1",
			SourceInput:     "github:org/repo//skills/verify-source-meta@abc1234a4b5c6d7e8f901234567890abcdef1234",
			SourceKind:      "github-source",
			ResolvedRef:     "abc1234a4b5c6d7e8f901234567890abcdef1234",
			FetchedAt:       "2026-05-23T00:00:00Z",
			SkillRootSHA256: installedRootHash,
		}); err != nil {
			t.Fatalf("writeSourceMetadata() error = %v", err)
		}

		ok, detail = verifyLockSourceMetadata(installedPath, lock)
		if !ok {
			t.Fatalf("expected source metadata pass, detail=%q", detail)
		}
		if !strings.Contains(detail, "metadata matches") {
			t.Fatalf("unexpected pass detail: %q", detail)
		}
	})
}

func TestVerifyLockDetectsSourceDrift(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "source-drift-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "source-drift-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lockPath := filepath.Join(installedPath, installLockFile)
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	var lock installLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("unmarshal lock: %v", err)
	}
	lock.Source.Type = "archive"
	updated, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal updated lock: %v", err)
	}
	if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
		t.Fatalf("write updated lock: %v", err)
	}

	reportOut, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if reportOut.Status != "DRIFTED" {
		t.Fatalf("status = %q, want DRIFTED", reportOut.Status)
	}

	var foundSourceCheck bool
	for _, c := range reportOut.Checks {
		if c.Name == "source" {
			foundSourceCheck = true
			if c.OK {
				t.Fatalf("source check should fail: %+v", c)
			}
		}
	}
	if !foundSourceCheck {
		t.Fatal("source check should exist")
	}
}

func TestVerifyLockStructureAndReportChecks(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "structure-report-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "structure-report-skill", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	base, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if base.Status != "VERIFIED" {
		t.Fatalf("status = %q, want VERIFIED", base.Status)
	}
	assertCheckOK(t, base.Checks, "lock_structure")
	assertCheckOK(t, base.Checks, "install_report")

	t.Run("invalid lock structure", func(t *testing.T) {
		lockPath := filepath.Join(installedPath, installLockFile)
		raw, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatalf("read lock: %v", err)
		}
		var lock installLock
		if err := json.Unmarshal(raw, &lock); err != nil {
			t.Fatalf("unmarshal lock: %v", err)
		}
		lock.Skill.Files = append(lock.Skill.Files, lockFileHash{
			Path:   lock.Skill.Files[0].Path,
			SHA256: lock.Skill.Files[0].SHA256,
			Bytes:  lock.Skill.Files[0].Bytes,
		})
		updated, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(lockPath, updated, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		out, err := verifyLock(installedPath)
		if err != nil {
			t.Fatalf("verifyLock() error = %v", err)
		}
		if out.Status != "DRIFTED" {
			t.Fatalf("status = %q, want DRIFTED", out.Status)
		}
		assertCheckFailedContains(t, out.Checks, "lock_structure", "duplicate lock file path")
	})
}

func TestVerifyInstallReportFailures(t *testing.T) {
	src := createSkillSourceForInstallTest(t, "report-failure-skill")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}
	seedReport := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "report-failure-skill", seedReport)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	lock, err := readInstallLock(filepath.Join(installedPath, installLockFile))
	if err != nil {
		t.Fatalf("readInstallLock() error = %v", err)
	}

	t.Run("missing report", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		originalReport, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read original report: %v", err)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report: %v", err)
		}
		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "failed to read install report") {
			t.Fatalf("expected missing report failure, got ok=%v detail=%q", ok, detail)
		}
		if err := os.WriteFile(reportPath, originalReport, 0o644); err != nil {
			t.Fatalf("restore report: %v", err)
		}
	})

	t.Run("source mismatch", func(t *testing.T) {
		reportPath := filepath.Join(installedPath, installReportFile)
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		var rep installReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		rep.Source.Input = "github:org/repo//skills/report-failure-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234"
		updated, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(reportPath, updated, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}

		ok, detail := verifyInstallReport(installedPath, lock)
		if ok || !strings.Contains(detail, "source does not match lock source") {
			t.Fatalf("expected source mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
}

func TestVerifyInstallReportValidationBranches(t *testing.T) {
	skillPath := t.TempDir()
	lock := installLock{
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	writeReport := func(t *testing.T, payload string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), []byte(payload), 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	t.Run("invalid json", func(t *testing.T) {
		writeReport(t, "{")
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "invalid install report JSON") {
			t.Fatalf("expected invalid json failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("invalid utf-8 payload", func(t *testing.T) {
		invalidUTF8Report := append([]byte(`{"schema_version":"0.1.0-draft","source":{"input":"/tmp/src","kind":"local-dir"},"policy_profile":"strict","decision":"PASS","note":"`), 0xff)
		invalidUTF8Report = append(invalidUTF8Report, []byte(`"}`)...)
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), invalidUTF8Report, 0o644); err != nil {
			t.Fatalf("write invalid utf-8 report: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportInvalidUTF8) {
			t.Fatalf("expected invalid utf-8 report failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("oversized report", func(t *testing.T) {
		origLimit := maxInstallReportFileBytes
		maxInstallReportFileBytes = 8
		t.Cleanup(func() { maxInstallReportFileBytes = origLimit })
		writeReport(t, `{"schema_version":"0.1.0-draft"}`)
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportTooLarge) {
			t.Fatalf("expected oversized report failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("report path is directory", func(t *testing.T) {
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		if err := os.Mkdir(reportPath, 0o755); err != nil {
			t.Fatalf("mkdir report path: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportSpecialFile) {
			t.Fatalf("expected special-file failure for directory report path, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report directory: %v", err)
		}
	})

	t.Run("report path is symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}
		reportPath := filepath.Join(skillPath, installReportFile)
		if err := os.Remove(reportPath); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove report file: %v", err)
		}
		target := filepath.Join(skillPath, "real-report.json")
		if err := os.WriteFile(target, []byte(`{"schema_version":"0.1.0-draft"}`), 0o644); err != nil {
			t.Fatalf("write real report: %v", err)
		}
		if err := os.Symlink("real-report.json", reportPath); err != nil {
			t.Fatalf("create report symlink: %v", err)
		}
		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, ruleInstallReportSymlink) {
			t.Fatalf("expected report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
		if err := os.Remove(reportPath); err != nil {
			t.Fatalf("remove report symlink: %v", err)
		}
	})

	t.Run("report path under ancestor symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o755); err != nil {
			t.Fatalf("mkdir real parent: %v", err)
		}
		realSkill := filepath.Join(realParent, "skill")
		if err := os.Mkdir(realSkill, 0o755); err != nil {
			t.Fatalf("mkdir real skill: %v", err)
		}
		valid := installReport{
			SchemaVersion: "0.1.0-draft",
			Source: source{
				Input: "/tmp/src",
				Kind:  "local-dir",
			},
			PolicyProfile: "strict",
			Decision:      "PASS",
			InstalledPath: filepath.Join(base, "link-parent", "skill"),
			Installed:     true,
		}
		raw, err := json.MarshalIndent(valid, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(realSkill, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
		linkParent := filepath.Join(base, "link-parent")
		if err := os.Symlink("real-parent", linkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}

		ok, detail := verifyInstallReport(filepath.Join(linkParent, "skill"), lock)
		if ok || !strings.Contains(detail, ruleInstallReportSymlink) {
			t.Fatalf("expected ancestor report symlink rejection, got ok=%v detail=%q", ok, detail)
		}
	})

	valid := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
	}
	raw, err := json.MarshalIndent(valid, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid report: %v", err)
	}
	writeReport(t, string(raw))
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected valid report check pass")
	}

	cases := []struct {
		name      string
		mutate    func(*installReport)
		detailHas string
	}{
		{
			name: "empty schema",
			mutate: func(r *installReport) {
				r.SchemaVersion = ""
			},
			detailHas: "schema_version is empty",
		},
		{
			name: "unsupported schema",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.0.0-test"
			},
			detailHas: "schema_version is unsupported",
		},
		{
			name: "schema has C0/C1 control character",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.1.0-draft\u008f"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u00850.1.0-draft"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.SchemaVersion = "\u0085"
			},
			detailHas: "schema_version must not contain C0/C1 control characters",
		},
		{
			name: "schema has surrounding whitespace",
			mutate: func(r *installReport) {
				r.SchemaVersion = " 0.1.0-draft "
			},
			detailHas: "schema_version must not contain leading or trailing whitespace",
		},
		{
			name: "schema has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.SchemaVersion = "0.1.0-draft\u200d"
			},
			detailHas: "schema_version must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty source input",
			mutate: func(r *installReport) {
				r.Source.Input = ""
			},
			detailHas: "source input is empty",
		},
		{
			name: "source input has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Source.Input = " " + r.Source.Input + " "
			},
			detailHas: "source input must not contain leading or trailing whitespace",
		},
		{
			name: "source input has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Source.Input = "/tmp/\u008fsrc"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Source.Input = "\u0085/tmp/src"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Source.Input = "\u0085"
			},
			detailHas: "source input must not contain C0/C1 control characters",
		},
		{
			name: "source input has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Source.Input = "/tmp/src\u200d"
			},
			detailHas: "source input must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty source kind",
			mutate: func(r *installReport) {
				r.Source.Kind = ""
			},
			detailHas: "source kind is empty",
		},
		{
			name: "source kind has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Source.Kind = " " + r.Source.Kind + " "
			},
			detailHas: "source kind must not contain leading or trailing whitespace",
		},
		{
			name: "source kind has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Source.Kind = "local-\u008fdir"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u0085local-dir"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Source.Kind = "\u0085"
			},
			detailHas: "source kind must not contain C0/C1 control characters",
		},
		{
			name: "source kind has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Source.Kind = "local-dir\u200d"
			},
			detailHas: "source kind must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty profile",
			mutate: func(r *installReport) {
				r.PolicyProfile = ""
			},
			detailHas: "policy profile is empty",
		},
		{
			name: "profile mismatch",
			mutate: func(r *installReport) {
				r.PolicyProfile = "team"
			},
			detailHas: "policy profile does not match",
		},
		{
			name: "profile has surrounding whitespace",
			mutate: func(r *installReport) {
				r.PolicyProfile = " strict "
			},
			detailHas: "policy profile must not contain leading or trailing whitespace",
		},
		{
			name: "profile has C0/C1 control character",
			mutate: func(r *installReport) {
				r.PolicyProfile = "stric\u008ft"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u0085strict"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.PolicyProfile = "\u0085"
			},
			detailHas: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "profile has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.PolicyProfile = "strict\u200d"
			},
			detailHas: "policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "profile not canonical lowercase",
			mutate: func(r *installReport) {
				r.PolicyProfile = "Strict"
			},
			detailHas: "policy profile must be canonical lowercase without surrounding whitespace",
		},
		{
			name: "decision mismatch",
			mutate: func(r *installReport) {
				r.Decision = "REJECTED"
			},
			detailHas: "decision does not match",
		},
		{
			name: "decision has surrounding whitespace",
			mutate: func(r *installReport) {
				r.Decision = " PASS "
			},
			detailHas: "decision must not contain leading or trailing whitespace",
		},
		{
			name: "decision has C0/C1 control character",
			mutate: func(r *installReport) {
				r.Decision = "PAS\u008fS"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.Decision = "\u0085PASS"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has C0/C1 control character only",
			mutate: func(r *installReport) {
				r.Decision = "\u0085"
			},
			detailHas: "decision must not contain C0/C1 control characters",
		},
		{
			name: "decision has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.Decision = "PASS\u200d"
			},
			detailHas: "decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "installed false",
			mutate: func(r *installReport) {
				r.Installed = false
			},
			detailHas: "installed must be true",
		},
		{
			name: "path mismatch",
			mutate: func(r *installReport) {
				r.InstalledPath = filepath.Join(skillPath, "other")
			},
			detailHas: "path mismatch",
		},
		{
			name: "installed path is empty",
			mutate: func(r *installReport) {
				r.InstalledPath = ""
			},
			detailHas: "installed path is empty",
		},
		{
			name: "installed path has surrounding whitespace",
			mutate: func(r *installReport) {
				r.InstalledPath = " " + r.InstalledPath + " "
			},
			detailHas: "installed path must not contain leading or trailing whitespace",
		},
		{
			name: "installed path has C0/C1 control character",
			mutate: func(r *installReport) {
				r.InstalledPath = filepath.Join(skillPath, "ok") + "\u008f"
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has C0/C1 control character at edge",
			mutate: func(r *installReport) {
				r.InstalledPath = "\u0085" + skillPath
			},
			detailHas: "installed path must not contain C0/C1 control characters",
		},
		{
			name: "installed path has unicode obfuscation character",
			mutate: func(r *installReport) {
				r.InstalledPath = r.InstalledPath + "\u200d"
			},
			detailHas: "installed path must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := valid
			tc.mutate(&rep)
			mutRaw, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}
			writeReport(t, string(mutRaw))

			ok, detail := verifyInstallReport(skillPath, lock)
			if ok || !strings.Contains(detail, tc.detailHas) {
				t.Fatalf("expected detail containing %q, got ok=%v detail=%q", tc.detailHas, ok, detail)
			}
		})
	}

	t.Run("decision must be pass even when matching lock decision", func(t *testing.T) {
		rep := valid
		rep.Decision = "REJECTED"
		mutRaw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		writeReport(t, string(mutRaw))

		mutLock := lock
		mutLock.Policy.Decision = "REJECTED"
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "decision must be pass") {
			t.Fatalf("expected pass-decision enforcement, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("findings summary mismatch", func(t *testing.T) {
		validRaw, err := json.MarshalIndent(valid, "", "  ")
		if err != nil {
			t.Fatalf("marshal valid report: %v", err)
		}
		writeReport(t, string(validRaw))

		mutLock := lock
		mutLock.Findings = lockFindingSummary{High: 1}
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "findings summary does not match") {
			t.Fatalf("expected findings summary mismatch, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("severity overrides mismatch", func(t *testing.T) {
		rep := valid
		rep.SeverityOverrides = []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "approved for internal fixture",
				ApprovedBy:        "sec-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
		}
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		writeReport(t, string(raw))

		mutLock := lock
		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "severity_overrides does not match") {
			t.Fatalf("expected severity_overrides mismatch, got ok=%v detail=%q", ok, detail)
		}
	})
}

func TestVerifyLockStructureValidationBranches(t *testing.T) {
	valid := installLock{
		Schema:      "gokui.lock/v1",
		Name:        "x",
		InstalledAt: "2026-05-23T00:00:00Z",
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/x",
			Kind:  "local-dir",
		},
		Skill: lockSkill{
			RootSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Files: []lockFileHash{
				{
					Path:   "SKILL.md",
					SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					Bytes:  10,
				},
			},
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
	}

	if ok, _ := verifyLockStructure(valid); !ok {
		t.Fatal("expected valid lock structure")
	}

	cases := []struct {
		name     string
		mutate   func(*installLock)
		detailIn string
	}{
		{
			name: "name has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Name = "x\u008f"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Name = "\u0085x"
			},
			detailIn: "name must not contain C0/C1 control characters",
		},
		{
			name: "name has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Name = "x\u200d"
			},
			detailIn: "name must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "empty installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = ""
			},
			detailIn: "installed_at is empty",
		},
		{
			name: "installed_at has C0/C1 control character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-23T00:00:00\u008fZ"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.InstalledAt = "\u00852026-05-23T00:00:00Z"
			},
			detailIn: "installed_at must not contain C0/C1 control characters",
		},
		{
			name: "installed_at has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.InstalledAt = "2026-05-23T00:00:00Z\u200d"
			},
			detailIn: "installed_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "invalid installed_at",
			mutate: func(l *installLock) {
				l.InstalledAt = "x"
			},
			detailIn: "must be RFC3339",
		},
		{
			name: "empty profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = ""
			},
			detailIn: "policy profile is empty",
		},
		{
			name: "unsupported profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = "enterprise"
			},
			detailIn: "policy profile is unsupported",
		},
		{
			name: "policy profile has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "stric\u008ft"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085strict"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has C0/C1 control character only",
			mutate: func(l *installLock) {
				l.Policy.Profile = "\u0085"
			},
			detailIn: "policy profile must not contain C0/C1 control characters",
		},
		{
			name: "policy profile has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Profile = "strict\u200d"
			},
			detailIn: "policy profile must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "non-canonical profile",
			mutate: func(l *installLock) {
				l.Policy.Profile = " Strict "
			},
			detailIn: "policy profile must be canonical lowercase without surrounding whitespace",
		},
		{
			name: "invalid decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "warn"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "rejected decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "rejected"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "uppercase decision",
			mutate: func(l *installLock) {
				l.Policy.Decision = "PASS"
			},
			detailIn: "lock policy decision must be canonical lowercase pass",
		},
		{
			name: "policy decision has C0/C1 control character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pas\u008fs"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has C0/C1 control character at edge",
			mutate: func(l *installLock) {
				l.Policy.Decision = "\u0085pass"
			},
			detailIn: "lock policy decision must not contain C0/C1 control characters",
		},
		{
			name: "policy decision has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Policy.Decision = "pass\u200d"
			},
			detailIn: "lock policy decision must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
		},
		{
			name: "policy decision has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Policy.Decision = " pass "
			},
			detailIn: "lock policy decision must not contain leading or trailing whitespace",
		},
		{
			name: "invalid root hash",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = "x"
			},
			detailIn: "root_sha256 must be a canonical lowercase 64-char hex digest",
		},
		{
			name: "uppercase root hash",
			mutate: func(l *installLock) {
				l.Skill.RootSHA256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
			},
			detailIn: "root_sha256 must be a canonical lowercase 64-char hex digest",
		},
		{
			name: "empty files",
			mutate: func(l *installLock) {
				l.Skill.Files = nil
			},
			detailIn: "files is empty",
		},
		{
			name: "invalid file path",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "../x"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has unicode obfuscation character",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = "SKILL.md\u200d"
			},
			detailIn: "file path is invalid",
		},
		{
			name: "file path has surrounding whitespace",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Path = " SKILL.md "
			},
			detailIn: "file path is invalid",
		},
		{
			name: "duplicate file path",
			mutate: func(l *installLock) {
				l.Skill.Files = append(l.Skill.Files, l.Skill.Files[0])
			},
			detailIn: "duplicate lock file path",
		},
		{
			name: "invalid file hash",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "x"
			},
			detailIn: "file sha256 is invalid",
		},
		{
			name: "uppercase file hash",
			mutate: func(l *installLock) {
				l.Skill.Files[0].SHA256 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
			},
			detailIn: "file sha256 is invalid",
		},
		{
			name: "negative bytes",
			mutate: func(l *installLock) {
				l.Skill.Files[0].Bytes = -1
			},
			detailIn: "bytes is negative",
		},
		{
			name: "invalid severity override entry",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides = []severityOverrideAudit{
					{
						RuleID:            "",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "test",
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
				}
			},
			detailIn: "severity_overrides is invalid",
		},
		{
			name: "duplicate severity override rule_id",
			mutate: func(l *installLock) {
				l.Policy.SeverityOverrides = []severityOverrideAudit{
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "medium",
						Justification:     "first",
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T00:00:00Z",
					},
					{
						RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
						PreviousSeverity:  "high",
						EffectiveSeverity: "low",
						Justification:     "second",
						ApprovedBy:        "tester",
						Source:            "policy-file",
						AppliedAt:         "2026-05-24T01:00:00Z",
					},
				}
			},
			detailIn: "severity_overrides is invalid",
		},
		{
			name: "negative findings summary",
			mutate: func(l *installLock) {
				l.Findings.High = -1
			},
			detailIn: "findings summary is invalid",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := valid
			l.Skill.Files = append([]lockFileHash(nil), valid.Skill.Files...)
			tc.mutate(&l)
			ok, detail := verifyLockStructure(l)
			if ok || !strings.Contains(detail, tc.detailIn) {
				t.Fatalf("expected failure containing %q, got ok=%v detail=%q", tc.detailIn, ok, detail)
			}
		})
	}
}

func TestLockVerifyHelpers(t *testing.T) {
	if !isCanonicalSHA256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") {
		t.Fatal("expected canonical digest to pass")
	}
	if isCanonicalSHA256Hex("x") {
		t.Fatal("invalid digest should fail canonical check")
	}
	if isCanonicalSHA256Hex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF") {
		t.Fatal("uppercase digest should fail canonical check")
	}
	if isCanonicalSHA256Hex(" 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ") {
		t.Fatal("surrounding whitespace should fail canonical check")
	}

	validPaths := []string{"SKILL.md", "references/readme.md", ".gokui-report.json"}
	for _, p := range validPaths {
		if !isValidLockRelativePath(p) {
			t.Fatalf("expected valid path: %s", p)
		}
	}
	invalidPaths := []string{"", ".", "..", "../x", "/x", `..\x`, `a\b`, "C:/x", "c:/x", "D:relative/path", "z:tmp", "SKILL.md\nx", "SKILL.md\tx", "SKILL.md\u0085x", "SKILL.md\u200dx", " SKILL.md", "SKILL.md ", string([]byte{'b', 'a', 'd', 0xff})}
	for _, p := range invalidPaths {
		if isValidLockRelativePath(p) {
			t.Fatalf("expected invalid path: %s", p)
		}
	}
}

func TestContainsSeverityOverrideDisallowedUnicode(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "plain ascii", in: "approved by reviewer", want: false},
		{name: "bidi override", in: "approved\u202E", want: true},
		{name: "bidi isolate", in: "approved\u2067", want: true},
		{name: "zero width joiner", in: "approved\u200D", want: true},
		{name: "variation selector", in: "approved\ufe0f", want: true},
		{name: "variation selector supplement", in: "approved\U000E0100", want: true},
		{name: "unicode tag", in: "approved\U000E0001", want: true},
		{name: "line separator", in: "approved\u2028", want: true},
		{name: "paragraph separator", in: "approved\u2029", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsSeverityOverrideDisallowedUnicode(tc.in); got != tc.want {
				t.Fatalf("containsSeverityOverrideDisallowedUnicode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestSeverityOverrideAuditHelpers(t *testing.T) {
	valid := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "medium",
			Justification:     "approved for controlled fixture",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}

	if err := validateSeverityOverrideAudit(valid); err != nil {
		t.Fatalf("validateSeverityOverrideAudit(valid) error = %v", err)
	}
	if !severityOverridesEqual(valid, valid) {
		t.Fatal("severityOverridesEqual(valid, valid) should be true")
	}
	if severityOverridesEqual(valid, nil) {
		t.Fatal("severityOverridesEqual(valid, nil) should be false")
	}

	t.Run("rejects invalid entries", func(t *testing.T) {
		cases := []struct {
			name       string
			override   severityOverrideAudit
			detailPart string
		}{
			{
				name: "empty rule_id",
				override: severityOverrideAudit{
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id is empty",
			},
			{
				name: "empty previous severity",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity is empty",
			},
			{
				name: "rule_id has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            " PROMPT_OVERRIDE_LANGUAGE ",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain leading or trailing whitespace",
			},
			{
				name: "rule_id has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE\u008f",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain C0/C1 control characters",
			},
			{
				name: "rule_id has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_\u200dLANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "rule_id must be uppercase snake case",
				override: severityOverrideAudit{
					RuleID:            "prompt_override_language",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "rule_id must be canonical uppercase snake case",
			},
			{
				name: "previous severity must be canonical",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "HIGH",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must be canonical severity",
			},
			{
				name: "previous severity has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high\u008f",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain C0/C1 control characters",
			},
			{
				name: "previous severity has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high\u200d",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "previous_severity must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty effective severity",
				override: severityOverrideAudit{
					RuleID:           "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity: "high",
					Justification:    "x",
					ApprovedBy:       "y",
					Source:           "policy-file",
					AppliedAt:        "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity is empty",
			},
			{
				name: "effective severity must be canonical",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "warn",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must be canonical severity",
			},
			{
				name: "effective severity has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium\u200d",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "effective_severity must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty justification",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification is empty",
			},
			{
				name: "justification has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "approved\u008f",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain C0/C1 control characters",
			},
			{
				name: "justification has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     " approved ",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain leading or trailing whitespace",
			},
			{
				name: "justification has bidi control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "approved\u202E",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "justification must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty approved_by",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by is empty",
			},
			{
				name: "approved_by has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "reviewer\u008f",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain C0/C1 control characters",
			},
			{
				name: "approved_by has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        " reviewer ",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain leading or trailing whitespace",
			},
			{
				name: "approved_by has zero-width character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "reviewer\u200d",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "approved_by must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "empty source",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source is empty",
			},
			{
				name: "source has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            " policy-file ",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain leading or trailing whitespace",
			},
			{
				name: "source has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file\u008f",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain C0/C1 control characters",
			},
			{
				name: "source has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file\u200d",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "source must be canonical lowercase",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "Policy-File",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must be canonical lowercase",
			},
			{
				name: "source must be allowed origin",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "manual-edit",
					AppliedAt:         "2026-05-24T00:00:00Z",
				},
				detailPart: "source must be an allowed origin",
			},
			{
				name: "empty applied_at",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
				},
				detailPart: "applied_at is empty",
			},
			{
				name: "invalid applied_at",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "not-rfc3339",
				},
				detailPart: "applied_at must be RFC3339",
			},
			{
				name: "applied_at has C0/C1 control character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z\u008f",
				},
				detailPart: "applied_at must not contain C0/C1 control characters",
			},
			{
				name: "applied_at has unicode obfuscation character",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         "2026-05-24T00:00:00Z\u200d",
				},
				detailPart: "applied_at must not contain Unicode bidi, zero-width, tag, or variation-selector characters",
			},
			{
				name: "applied_at has surrounding whitespace",
				override: severityOverrideAudit{
					RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
					PreviousSeverity:  "high",
					EffectiveSeverity: "medium",
					Justification:     "x",
					ApprovedBy:        "y",
					Source:            "policy-file",
					AppliedAt:         " 2026-05-24T00:00:00Z ",
				},
				detailPart: "applied_at must not contain leading or trailing whitespace",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateSeverityOverrideAudit([]severityOverrideAudit{tc.override})
				if err == nil || !strings.Contains(err.Error(), tc.detailPart) {
					t.Fatalf("expected validation detail %q, got err=%v", tc.detailPart, err)
				}
			})
		}
	})

	t.Run("rejects duplicate rule_id entries", func(t *testing.T) {
		dup := []severityOverrideAudit{
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "medium",
				Justification:     "approved first",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T00:00:00Z",
			},
			{
				RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
				PreviousSeverity:  "high",
				EffectiveSeverity: "low",
				Justification:     "approved duplicate",
				ApprovedBy:        "security-reviewer",
				Source:            "policy-file",
				AppliedAt:         "2026-05-24T01:00:00Z",
			},
		}
		err := validateSeverityOverrideAudit(dup)
		if err == nil || !strings.Contains(err.Error(), "duplicate rule_id is not allowed") {
			t.Fatalf("expected duplicate rule_id validation error, got %v", err)
		}
	})
}

func TestLockFindingSummaryAndSeverityOverrideEqualityBranches(t *testing.T) {
	if err := validateLockFindingSummary(lockFindingSummary{
		Critical: 0,
		High:     1,
		Medium:   2,
		Low:      3,
	}); err != nil {
		t.Fatalf("validateLockFindingSummary(valid) error = %v", err)
	}

	negCases := []struct {
		name    string
		summary lockFindingSummary
		detail  string
	}{
		{
			name:    "critical negative",
			summary: lockFindingSummary{Critical: -1},
			detail:  "critical count",
		},
		{
			name:    "high negative",
			summary: lockFindingSummary{High: -1},
			detail:  "high count",
		},
		{
			name:    "medium negative",
			summary: lockFindingSummary{Medium: -1},
			detail:  "medium count",
		},
		{
			name:    "low negative",
			summary: lockFindingSummary{Low: -1},
			detail:  "low count",
		},
	}
	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLockFindingSummary(tc.summary)
			if err == nil || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("expected %q validation error, got %v", tc.detail, err)
			}
		})
	}

	left := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "medium",
			Justification:     "approved",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}
	right := []severityOverrideAudit{
		{
			RuleID:            "PROMPT_OVERRIDE_LANGUAGE",
			PreviousSeverity:  "high",
			EffectiveSeverity: "low",
			Justification:     "approved",
			ApprovedBy:        "security-reviewer",
			Source:            "policy-file",
			AppliedAt:         "2026-05-24T00:00:00Z",
		},
	}
	if severityOverridesEqual(left, right) {
		t.Fatal("severityOverridesEqual should be false for same-length slices with different entries")
	}
}

func TestLockRelativePathProperties(t *testing.T) {
	t.Run("windows drive prefixes are always invalid", func(t *testing.T) {
		prop := func(letter uint8, tail string) bool {
			drive := byte('A' + (letter % 26))
			path := fmt.Sprintf("%c:%s", drive, tail)
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("drive-prefix property failed: %v", err)
		}
	})

	t.Run("paths with backslash are always invalid", func(t *testing.T) {
		prop := func(a string, b string) bool {
			path := a + `\` + b
			return !isValidLockRelativePath(path)
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
			t.Fatalf("backslash property failed: %v", err)
		}
	})
}

func TestVerifyInstallReportDecisionAndFindingsInvariant(t *testing.T) {
	skillPath := t.TempDir()
	lock := installLock{
		Source: lockSource{
			Type:  "local",
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		Policy: lockPolicy{
			Profile:  "strict",
			Decision: "pass",
		},
		Findings: lockFindingSummary{
			Critical: 0,
			High:     1,
			Medium:   0,
			Low:      0,
		},
	}
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source: source{
			Input: "/tmp/src",
			Kind:  "local-dir",
		},
		PolicyProfile: "strict",
		Decision:      "PASS",
		InstalledPath: skillPath,
		Installed:     true,
		Findings: []inspectFinding{
			{ID: "UNPINNED_RUNTIME_TOOL", Severity: "high", File: "SKILL.md", Line: 1, Summary: "x"},
		},
	}

	writeReport := func(t *testing.T, in installReport) {
		t.Helper()
		raw, err := json.MarshalIndent(in, "", "  ")
		if err != nil {
			t.Fatalf("marshal report: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillPath, installReportFile), raw, 0o644); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}

	writeReport(t, report)
	if ok, _ := verifyInstallReport(skillPath, lock); !ok {
		t.Fatal("expected baseline install report check pass")
	}

	t.Run("decision must be pass", func(t *testing.T) {
		mutLock := lock
		mutLock.Policy.Decision = "rejected"

		mutReport := report
		mutReport.Decision = "REJECTED"
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, mutLock)
		if ok || !strings.Contains(detail, "decision must be pass") {
			t.Fatalf("expected pass-only decision failure, got ok=%v detail=%q", ok, detail)
		}
	})

	t.Run("findings summary mismatch", func(t *testing.T) {
		mutReport := report
		mutReport.Findings = nil
		writeReport(t, mutReport)

		ok, detail := verifyInstallReport(skillPath, lock)
		if ok || !strings.Contains(detail, "findings summary does not match lock findings") {
			t.Fatalf("expected findings mismatch failure, got ok=%v detail=%q", ok, detail)
		}
	})
}

func assertCheckOK(t *testing.T, checks []lockVerifyCheck, name string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if !c.OK {
				t.Fatalf("check %s should pass: %+v", name, c)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}

func assertCheckFailedContains(t *testing.T, checks []lockVerifyCheck, name string, contains string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if c.OK {
				t.Fatalf("check %s should fail: %+v", name, c)
			}
			if !strings.Contains(c.Detail, contains) {
				t.Fatalf("check %s detail = %q, want contains %q", name, c.Detail, contains)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}

func assertCheckCode(t *testing.T, checks []lockVerifyCheck, name string, code string) {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			if c.Code != code {
				t.Fatalf("check %s code = %q, want %q", name, c.Code, code)
			}
			return
		}
	}
	t.Fatalf("check %s not found", name)
}
