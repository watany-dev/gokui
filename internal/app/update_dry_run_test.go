package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunUpdateDryRunStatuses(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	src := createSkillSourceForInstallTest(t, "update-skill")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	if _, _, err := installSkillAtomic(src, targetRoot, "update-skill", report); err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runUpdate(up-to-date) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var upToDateReport updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &upToDateReport); err != nil {
		t.Fatalf("json unmarshal update report: %v", err)
	}
	if upToDateReport.Summary.UpToDate != 1 {
		t.Fatalf("expected one up-to-date skill, got %+v", upToDateReport.Summary)
	}
	if len(upToDateReport.Skills) != 1 || upToDateReport.Skills[0].Status != "UP_TO_DATE" {
		t.Fatalf("unexpected skill status: %+v", upToDateReport.Skills)
	}
	if upToDateReport.Skills[0].ErrorCode != updateCodeUpToDate {
		t.Fatalf("unexpected up-to-date error_code: %+v", upToDateReport.Skills[0])
	}

	// Source changed after install -> dry-run should report CHANGED.
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("changed content"), 0o644); err != nil {
		t.Fatalf("mutate README: %v", err)
	}
	if err := os.WriteFile(filepath.Join(src, "notes.md"), []byte("see https://example.com/new"), 0o644); err != nil {
		t.Fatalf("write notes with new URL: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(filepath.Join(src, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
			t.Fatalf("write executable script: %v", err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runUpdate(changed) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var changedReport updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &changedReport); err != nil {
		t.Fatalf("json unmarshal changed report: %v", err)
	}
	if changedReport.Summary.Changed != 1 {
		t.Fatalf("expected one changed skill, got %+v", changedReport.Summary)
	}
	if changedReport.Skills[0].Status != "CHANGED" {
		t.Fatalf("expected CHANGED status, got %+v", changedReport.Skills[0])
	}
	if changedReport.Skills[0].ErrorCode != updateCodeChanged {
		t.Fatalf("unexpected changed error_code: %+v", changedReport.Skills[0])
	}
	if len(changedReport.Skills[0].NewURLs) == 0 {
		t.Fatalf("expected new URL detection, got %+v", changedReport.Skills[0])
	}
	if runtime.GOOS != "windows" && len(changedReport.Skills[0].NewExecutableFiles) == 0 {
		t.Fatalf("expected new executable detection, got %+v", changedReport.Skills[0])
	}
}

func TestRunUpdateDryRunDetectsSchemeRelativeNewURLs(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	src := createSkillSourceForInstallTest(t, "update-scheme-relative-url-skill")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	if _, _, err := installSkillAtomic(src, targetRoot, "update-scheme-relative-url-skill", report); err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("see //example.com/new-resource"), 0o644); err != nil {
		t.Fatalf("write scheme-relative URL content: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runUpdate(scheme-relative url) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var updateOut updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &updateOut); err != nil {
		t.Fatalf("json unmarshal update output: %v", err)
	}
	if len(updateOut.Skills) != 1 {
		t.Fatalf("skills length = %d, want 1", len(updateOut.Skills))
	}
	if updateOut.Skills[0].Status != "CHANGED" {
		t.Fatalf("status = %q, want CHANGED", updateOut.Skills[0].Status)
	}

	found := false
	for _, u := range updateOut.Skills[0].NewURLs {
		if u == "//example.com/new-resource" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected scheme-relative URL in new_urls, got %+v", updateOut.Skills[0].NewURLs)
	}
}

func TestRunUpdateDryRunDetectsUppercaseSchemeNewURLs(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	src := createSkillSourceForInstallTest(t, "update-uppercase-scheme-url-skill")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	if _, _, err := installSkillAtomic(src, targetRoot, "update-uppercase-scheme-url-skill", report); err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("see HTTPS://EXAMPLE.com/new-resource"), 0o644); err != nil {
		t.Fatalf("write uppercase-scheme URL content: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runUpdate(uppercase-scheme url) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var updateOut updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &updateOut); err != nil {
		t.Fatalf("json unmarshal update output: %v", err)
	}
	if len(updateOut.Skills) != 1 {
		t.Fatalf("skills length = %d, want 1", len(updateOut.Skills))
	}
	if updateOut.Skills[0].Status != "CHANGED" {
		t.Fatalf("status = %q, want CHANGED", updateOut.Skills[0].Status)
	}

	found := false
	for _, u := range updateOut.Skills[0].NewURLs {
		if u == "HTTPS://EXAMPLE.com/new-resource" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected uppercase-scheme URL in new_urls, got %+v", updateOut.Skills[0].NewURLs)
	}
}

func TestRunUpdateDryRunDetectsBracketedIPv6NewURLs(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	src := createSkillSourceForInstallTest(t, "update-bracketed-ipv6-url-skill")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	if _, _, err := installSkillAtomic(src, targetRoot, "update-bracketed-ipv6-url-skill", report); err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	content := "see https://[2001:db8::1]/pkg and //[2001:db8::2]/boot"
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write bracketed ipv6 URL content: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runUpdate(bracketed ipv6 url) code = %d, want 2\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var updateOut updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &updateOut); err != nil {
		t.Fatalf("json unmarshal update output: %v", err)
	}
	if len(updateOut.Skills) != 1 {
		t.Fatalf("skills length = %d, want 1", len(updateOut.Skills))
	}
	if updateOut.Skills[0].Status != "REJECTED" {
		t.Fatalf("status = %q, want REJECTED", updateOut.Skills[0].Status)
	}

	want := map[string]bool{
		"https://[2001:db8::1]/pkg": false,
		"//[2001:db8::2]/boot":      false,
	}
	for _, u := range updateOut.Skills[0].NewURLs {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	for u, found := range want {
		if !found {
			t.Fatalf("expected bracketed ipv6 URL %q in new_urls, got %+v", u, updateOut.Skills[0].NewURLs)
		}
	}
}

func TestRunUpdateDryRunDoesNotMutateInstalledLockState(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "skills")
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		t.Fatalf("mkdir target root: %v", err)
	}

	src := createSkillSourceForInstallTest(t, "update-dry-run-lock-stability")
	report := installReport{
		SchemaVersion: "0.1.0-draft",
		Source:        source{Input: src, Kind: "local-dir"},
		PolicyProfile: "strict",
		Decision:      "PASS",
	}
	installedPath, _, err := installSkillAtomic(src, targetRoot, "update-dry-run-lock-stability", report)
	if err != nil {
		t.Fatalf("installSkillAtomic() error = %v", err)
	}

	// Mutate source to ensure dry-run evaluates a CHANGED candidate.
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte("changed content"), 0o644); err != nil {
		t.Fatalf("mutate source README: %v", err)
	}

	var stdout strings.Builder
	var stderr strings.Builder
	code := runUpdate([]string{"--dry-run", "--target", "custom:" + targetRoot, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runUpdate(dry-run changed) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty, got %q", stderr.String())
	}

	var updateOut updateReport
	if err := json.Unmarshal([]byte(stdout.String()), &updateOut); err != nil {
		t.Fatalf("json unmarshal update output: %v", err)
	}
	if updateOut.Summary.Changed != 1 {
		t.Fatalf("changed summary = %+v, want one changed skill", updateOut.Summary)
	}
	if len(updateOut.Skills) != 1 || updateOut.Skills[0].Status != "CHANGED" {
		t.Fatalf("unexpected update skill status: %+v", updateOut.Skills)
	}

	// Dry-run must not mutate installed files/lock baseline.
	lockState, err := verifyLock(installedPath)
	if err != nil {
		t.Fatalf("verifyLock() error = %v", err)
	}
	if lockState.Status != "VERIFIED" {
		t.Fatalf("lock status after dry-run = %q, want VERIFIED", lockState.Status)
	}
	if len(lockState.Drift.MissingFiles) != 0 || len(lockState.Drift.ChangedFiles) != 0 || len(lockState.Drift.UnexpectedFiles) != 0 {
		t.Fatalf("unexpected drift after dry-run: %+v", lockState.Drift)
	}

	stdout.Reset()
	stderr.Reset()
	code = runLockVerify([]string{installedPath, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runLockVerify(after dry-run) code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty for lock verify, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "\"status\": \"VERIFIED\"") {
		t.Fatalf("lock verify output should remain VERIFIED, got %q", stdout.String())
	}
}
