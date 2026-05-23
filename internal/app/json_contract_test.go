package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestInspectJSONContract(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runInspect([]string{filepath.FromSlash("../../fixtures/clean-skill"), "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runInspect() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal inspect output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"pre_release",
		"source",
		"decision",
		"findings",
		"note",
	})

	var sourceObj map[string]json.RawMessage
	if err := json.Unmarshal(top["source"], &sourceObj); err != nil {
		t.Fatalf("json unmarshal inspect source: %v", err)
	}
	assertJSONHasKeysContract(t, sourceObj, []string{"input", "kind"})
}

func TestFetchJSONContract(t *testing.T) {
	origFetch := fetchGitHubSkill
	t.Cleanup(func() { fetchGitHubSkill = origFetch })

	sourceDir := createSkillSourceForInstallTest(t, "fetch-json-contract")
	fetchGitHubSkill = func(spec srcpkg.GitHubSpec) (string, func(), error) {
		return sourceDir, nil, nil
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runFetch([]string{
		"github:org/repo//skills/fetch-json-contract@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
		"--out", t.TempDir(),
		"--format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runFetch() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal fetch output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"source",
		"output",
		"decision",
		"note",
	})

	var sourceObj map[string]json.RawMessage
	if err := json.Unmarshal(top["source"], &sourceObj); err != nil {
		t.Fatalf("json unmarshal fetch source: %v", err)
	}
	assertJSONHasKeysContract(t, sourceObj, []string{"input", "kind"})
}

func TestFetchJSONErrorContract(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runFetch([]string{"--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runFetch(json error) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal fetch error output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"status",
		"error_code",
		"message",
		"source",
		"output",
		"note",
	})
}

func TestInstallMetadataJSONContract(t *testing.T) {
	sourceDir := createSkillSourceForInstallTest(t, "install-json-contract")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runInstall([]string{
		sourceDir,
		"--target", "custom:" + targetRoot,
		"--profile", "strict",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runInstall() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	skillPath := filepath.Join(targetRoot, "install-json-contract")
	reportRaw, err := os.ReadFile(filepath.Join(skillPath, installReportFile))
	if err != nil {
		t.Fatalf("read install report: %v", err)
	}
	lockRaw, err := os.ReadFile(filepath.Join(skillPath, installLockFile))
	if err != nil {
		t.Fatalf("read install lock: %v", err)
	}

	var report map[string]json.RawMessage
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatalf("json unmarshal install report: %v", err)
	}
	assertJSONHasKeysContract(t, report, []string{
		"schema_version",
		"source",
		"policy_profile",
		"decision",
		"error_code",
		"findings",
		"installed_path",
		"installed",
		"note",
	})

	var reportSource map[string]json.RawMessage
	if err := json.Unmarshal(report["source"], &reportSource); err != nil {
		t.Fatalf("json unmarshal install report source: %v", err)
	}
	assertJSONHasKeysContract(t, reportSource, []string{"input", "kind"})

	var lock map[string]json.RawMessage
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatalf("json unmarshal install lock: %v", err)
	}
	assertJSONHasKeysContract(t, lock, []string{
		"schema",
		"name",
		"installed_at",
		"source",
		"skill",
		"policy",
		"findings",
	})
}

func TestInstallJSONContract(t *testing.T) {
	sourceDir := createSkillSourceForInstallTest(t, "install-command-json-contract")
	targetRoot := filepath.Join(t.TempDir(), "skills")

	var stdout strings.Builder
	var stderr strings.Builder
	code := runInstall([]string{
		sourceDir,
		"--target", "custom:" + targetRoot,
		"--profile", "strict",
		"--format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runInstall(json) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal install output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"source",
		"policy_profile",
		"decision",
		"error_code",
		"findings",
		"installed_path",
		"installed",
		"note",
	})
}

func TestInstallJSONErrorContract(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runInstall([]string{"--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runInstall(json error) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal install error output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"status",
		"error_code",
		"message",
		"source",
		"target",
		"policy_profile",
		"note",
	})
}

func TestLockVerifyJSONContract(t *testing.T) {
	sourceDir := createSkillSourceForInstallTest(t, "lock-verify-json-contract")
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	report := installReport{
		SchemaVersion: reportSchemaVersion,
		Source:        source{Input: sourceDir, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(sourceDir, targetRoot, "lock-verify-json-contract", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify() code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal lock verify output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"skill_path",
		"status",
		"checks",
		"drift",
		"note",
	})

	var checks []map[string]json.RawMessage
	if err := json.Unmarshal(top["checks"], &checks); err != nil {
		t.Fatalf("json unmarshal lock verify checks: %v", err)
	}
	if len(checks) == 0 {
		t.Fatal("lock verify checks should not be empty")
	}
	for _, c := range checks {
		assertJSONHasKeysContract(t, c, []string{"code", "name", "ok", "detail"})
	}

	var drift map[string]json.RawMessage
	if err := json.Unmarshal(top["drift"], &drift); err != nil {
		t.Fatalf("json unmarshal lock verify drift: %v", err)
	}
	assertJSONHasKeysContract(t, drift, []string{
		"missing_files",
		"changed_files",
		"unexpected_files",
	})
}

func TestLockVerifyJSONErrorContract(t *testing.T) {
	var stdout strings.Builder
	var stderr strings.Builder

	code := runLockVerify([]string{filepath.Join(t.TempDir(), "missing"), "--format", "json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runLockVerify(json error) code = %d, want 1\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for json error output, got %q", stderr.String())
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &top); err != nil {
		t.Fatalf("json unmarshal lock verify error output: %v", err)
	}
	assertJSONHasKeysContract(t, top, []string{
		"schema_version",
		"skill_path",
		"status",
		"error_code",
		"message",
		"note",
	})
}

func assertJSONHasKeysContract(t *testing.T, obj map[string]json.RawMessage, keys []string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := obj[key]; !ok {
			t.Fatalf("missing json key %q in object: %+v", key, obj)
		}
	}
}
