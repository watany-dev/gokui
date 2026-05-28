package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	policypkg "github.com/watany-dev/gokui/internal/policy"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
)

func TestUpdateHelpers(t *testing.T) {
	t.Run("setDiff and mapKeysSorted", func(t *testing.T) {
		got := setDiff([]string{"b", "a", "c"}, []string{"b"})
		want := []string{"a", "c"}
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("setDiff() = %+v, want %+v", got, want)
		}

		keys := mapKeysSorted(map[string]struct{}{"z": {}, "a": {}})
		if len(keys) != 2 || keys[0] != "a" || keys[1] != "z" {
			t.Fatalf("mapKeysSorted() = %+v", keys)
		}
	})

	t.Run("collectURLs and markdown-like files", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("see https://example.com/a"), 0o644); err != nil {
			t.Fatalf("write readme: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "data.bin"), []byte("https://example.com/bin"), 0o644); err != nil {
			t.Fatalf("write binary-ish: %v", err)
		}
		urls, err := collectURLs(root)
		if err != nil {
			t.Fatalf("collectURLs() error = %v", err)
		}
		if len(urls) != 1 || urls[0] != "https://example.com/a" {
			t.Fatalf("unexpected urls: %+v", urls)
		}
		if !isMarkdownLikeFile("notes.txt") || !isMarkdownLikeFile("README.MD") || isMarkdownLikeFile("main.go") {
			t.Fatalf("isMarkdownLikeFile() unexpected behavior")
		}
	})

	t.Run("relative path messages", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "nested", "SKILL.md")
		if got := relativePathForMessage(path, root); got != "nested/SKILL.md" {
			t.Fatalf("relativePathForMessage() = %q, want nested/SKILL.md", got)
		}
		if got := relativePathForMessage("relative/SKILL.md", root); got != "relative/SKILL.md" {
			t.Fatalf("relativePathForMessage() fallback = %q, want relative/SKILL.md", got)
		}
	})

	t.Run("collectURLs and executable collection errors", func(t *testing.T) {
		_, err := collectURLs(filepath.Join(t.TempDir(), "missing"))
		if err == nil {
			t.Fatal("collectURLs should fail for missing root")
		}

		_, err = collectExecutableFiles(filepath.Join(t.TempDir(), "missing"))
		if err == nil {
			t.Fatal("collectExecutableFiles should fail for missing root")
		}

		if runtime.GOOS != "windows" {
			root := t.TempDir()
			blocked := filepath.Join(root, "blocked.md")
			if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
				t.Fatalf("write blocked file: %v", err)
			}
			if err := os.Chmod(blocked, 0o000); err != nil {
				t.Fatalf("chmod blocked file: %v", err)
			}
			defer os.Chmod(blocked, 0o644)
			_, err := collectURLs(root)
			if err == nil {
				t.Fatal("collectURLs should fail for unreadable markdown file")
			}
		}
	})

	t.Run("collectURLs rejects symlink root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		parent := t.TempDir()
		realRoot := filepath.Join(parent, "real-root")
		if err := os.Mkdir(realRoot, 0o755); err != nil {
			t.Fatalf("mkdir real root: %v", err)
		}
		linkRoot := filepath.Join(parent, "root-link")
		if err := os.Symlink("real-root", linkRoot); err != nil {
			t.Fatalf("create root symlink: %v", err)
		}

		_, err := collectURLs(linkRoot)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSymlink.ID) {
			t.Fatalf("expected URL-scan root symlink rejection, got %v", err)
		}
	})

	t.Run("collectURLs rejects non-directory root", func(t *testing.T) {
		rootFile := filepath.Join(t.TempDir(), "not-a-dir.md")
		if err := os.WriteFile(rootFile, []byte("https://example.com"), 0o644); err != nil {
			t.Fatalf("write root file: %v", err)
		}

		_, err := collectURLs(rootFile)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSpecialFile.ID) {
			t.Fatalf("expected URL-scan non-directory rejection, got %v", err)
		}
	})

	t.Run("collectURLs rejects symlink markdown inputs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		root := t.TempDir()
		target := filepath.Join(root, "real.md")
		if err := os.WriteFile(target, []byte("https://example.com"), 0o644); err != nil {
			t.Fatalf("write target markdown: %v", err)
		}
		if err := os.Symlink("real.md", filepath.Join(root, "link.md")); err != nil {
			t.Fatalf("create markdown symlink: %v", err)
		}

		_, err := collectURLs(root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSymlink.ID) {
			t.Fatalf("expected URL-scan symlink rejection, got %v", err)
		}
	})

	t.Run("collectURLs rejects non-regular markdown inputs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on windows")
		}

		root := t.TempDir()
		fifoPath := filepath.Join(root, "pipe.md")
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo command not available")
		}
		if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
			t.Skipf("mkfifo unsupported in this environment: %v", err)
		}

		_, err := collectURLs(root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSpecialFile.ID) {
			t.Fatalf("expected URL-scan special-file rejection, got %v", err)
		}
	})

	t.Run("collectURLs ignores non-markdown symlink inputs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		root := t.TempDir()
		target := filepath.Join(root, "real.bin")
		if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
			t.Fatalf("write target file: %v", err)
		}
		if err := os.Symlink("real.bin", filepath.Join(root, "link.bin")); err != nil {
			t.Fatalf("create non-markdown symlink: %v", err)
		}

		urls, err := collectURLs(root)
		if err != nil {
			t.Fatalf("collectURLs() should ignore non-markdown symlink, got error %v", err)
		}
		if len(urls) != 0 {
			t.Fatalf("collectURLs() should return no URLs, got %+v", urls)
		}
	})

	t.Run("collectExecutableFiles rejects symlink inputs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		root := t.TempDir()
		target := filepath.Join(root, "run.sh")
		if err := os.WriteFile(target, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
			t.Fatalf("write executable target: %v", err)
		}
		if err := os.Symlink("run.sh", filepath.Join(root, "link.sh")); err != nil {
			t.Fatalf("create executable symlink: %v", err)
		}

		_, err := collectExecutableFiles(root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateExecutableScanSymlink.ID) {
			t.Fatalf("expected executable-scan symlink rejection, got %v", err)
		}
	})

	t.Run("collectExecutableFiles returns executable relative paths", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("executable mode bits differ on windows")
		}

		root := t.TempDir()
		binDir := filepath.Join(root, "bin")
		if err := os.Mkdir(binDir, 0o755); err != nil {
			t.Fatalf("mkdir bin: %v", err)
		}
		if err := os.WriteFile(filepath.Join(binDir, "run.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write executable: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("not executable"), 0o644); err != nil {
			t.Fatalf("write non-executable: %v", err)
		}

		got, err := collectExecutableFiles(root)
		if err != nil {
			t.Fatalf("collectExecutableFiles() error = %v", err)
		}
		if len(got) != 1 || got[0] != "bin/run.sh" {
			t.Fatalf("collectExecutableFiles() = %+v, want [bin/run.sh]", got)
		}
	})

	t.Run("collectExecutableFiles rejects symlink root", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink permissions differ on windows")
		}

		parent := t.TempDir()
		realRoot := filepath.Join(parent, "real-root")
		if err := os.Mkdir(realRoot, 0o755); err != nil {
			t.Fatalf("mkdir real root: %v", err)
		}
		linkRoot := filepath.Join(parent, "root-link")
		if err := os.Symlink("real-root", linkRoot); err != nil {
			t.Fatalf("create root symlink: %v", err)
		}

		_, err := collectExecutableFiles(linkRoot)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateExecutableScanSymlink.ID) {
			t.Fatalf("expected executable-scan root symlink rejection, got %v", err)
		}
	})

	t.Run("collectExecutableFiles rejects non-directory root", func(t *testing.T) {
		rootFile := filepath.Join(t.TempDir(), "not-a-dir.sh")
		if err := os.WriteFile(rootFile, []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatalf("write root file: %v", err)
		}

		_, err := collectExecutableFiles(rootFile)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateExecutableScanSpecialFile.ID) {
			t.Fatalf("expected executable-scan non-directory rejection, got %v", err)
		}
	})

	t.Run("collectExecutableFiles rejects non-regular inputs", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on windows")
		}

		root := t.TempDir()
		fifoPath := filepath.Join(root, "pipe.sh")
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo command not available")
		}
		if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
			t.Skipf("mkfifo unsupported in this environment: %v", err)
		}

		_, err := collectExecutableFiles(root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateExecutableScanSpecialFile.ID) {
			t.Fatalf("expected executable-scan special-file rejection, got %v", err)
		}
	})

	t.Run("collectURLs rejects oversized markdown files", func(t *testing.T) {
		root := t.TempDir()
		huge := strings.Repeat("a", int(updateMaxURLScanFileBytes)+1)
		if err := os.WriteFile(filepath.Join(root, "huge.md"), []byte(huge), 0o644); err != nil {
			t.Fatalf("write huge markdown: %v", err)
		}
		_, err := collectURLs(root)
		if err == nil || !strings.Contains(err.Error(), "exceeds URL scan size limit") {
			t.Fatalf("expected oversized markdown error, got %v", err)
		}
	})

	t.Run("readURLScanContent reports read and size errors", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "big.md")

		_, err := readURLScanContent(bytes.NewReader([]byte(strings.Repeat("a", int(updateMaxURLScanFileBytes)+1))), path, root)
		if err == nil || !strings.Contains(err.Error(), "exceeds URL scan size limit") {
			t.Fatalf("expected size-limit error, got %v", err)
		}

		_, err = readURLScanContent(errorReader{err: errors.New("read fail")}, path, root)
		if err == nil || !strings.Contains(err.Error(), "failed to read file for URL scan") {
			t.Fatalf("expected read error, got %v", err)
		}

		_, err = readURLScanContent(bytes.NewReader([]byte{0xff}), path, root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanInvalidUTF8.ID) {
			t.Fatalf("expected invalid utf-8 URL scan error, got %v", err)
		}
	})

	t.Run("collectURLs enforces max scan file count", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 3; i++ {
			name := filepath.Join(root, fmt.Sprintf("doc-%d.md", i))
			if err := os.WriteFile(name, []byte("https://example.com"), 0o644); err != nil {
				t.Fatalf("write markdown %d: %v", i, err)
			}
		}
		_, err := collectURLsWithLimits(root, updateScanLimits{MaxURLScanFileBytes: updateMaxURLScanFileBytes, MaxScanFiles: 2})
		if err == nil || !strings.Contains(err.Error(), "URL scan exceeded max file count") {
			t.Fatalf("expected URL scan max-file error, got %v", err)
		}
	})

	t.Run("collectURLs rejects non-utf8 markdown inputs", func(t *testing.T) {
		root := t.TempDir()
		invalid := append([]byte("prefix"), 0xff)
		if err := os.WriteFile(filepath.Join(root, "bad.md"), invalid, 0o644); err != nil {
			t.Fatalf("write invalid utf-8 markdown: %v", err)
		}
		_, err := collectURLs(root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanInvalidUTF8.ID) {
			t.Fatalf("expected URL scan invalid-utf8 error, got %v", err)
		}
	})

	t.Run("ensureURLScanRegularFile classifies regular and non-regular files", func(t *testing.T) {
		root := t.TempDir()

		regularPath := filepath.Join(root, "doc.md")
		if err := os.WriteFile(regularPath, []byte("ok"), 0o644); err != nil {
			t.Fatalf("write regular markdown: %v", err)
		}
		regularInfo, err := os.Lstat(regularPath)
		if err != nil {
			t.Fatalf("lstat regular markdown: %v", err)
		}
		if err := ensureURLScanRegularFile(regularInfo, regularPath, root); err != nil {
			t.Fatalf("regular markdown should pass validation, got %v", err)
		}

		dirInfo, err := os.Lstat(root)
		if err != nil {
			t.Fatalf("lstat root dir: %v", err)
		}
		err = ensureURLScanRegularFile(dirInfo, root, root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSpecialFile.ID) {
			t.Fatalf("expected non-regular file error, got %v", err)
		}
	})

	t.Run("ensureURLScanStableFile detects source replacement", func(t *testing.T) {
		root := t.TempDir()
		firstPath := filepath.Join(root, "first.md")
		if err := os.WriteFile(firstPath, []byte("one"), 0o644); err != nil {
			t.Fatalf("write first markdown: %v", err)
		}
		secondPath := filepath.Join(root, "second.md")
		if err := os.WriteFile(secondPath, []byte("two"), 0o644); err != nil {
			t.Fatalf("write second markdown: %v", err)
		}

		firstInfo, err := os.Lstat(firstPath)
		if err != nil {
			t.Fatalf("lstat first markdown: %v", err)
		}
		secondInfo, err := os.Lstat(secondPath)
		if err != nil {
			t.Fatalf("lstat second markdown: %v", err)
		}

		if err := ensureURLScanStableFile(firstInfo, firstInfo, firstPath, root); err != nil {
			t.Fatalf("same file identity should pass, got %v", err)
		}
		err = ensureURLScanStableFile(firstInfo, secondInfo, secondPath, root)
		if err == nil || !strings.Contains(err.Error(), rulepkg.UpdateURLScanSourceChangedDuringRead.ID) {
			t.Fatalf("expected changed-source error, got %v", err)
		}
	})

	t.Run("collectExecutableFiles enforces max scan file count", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 3; i++ {
			name := filepath.Join(root, fmt.Sprintf("run-%d.sh", i))
			if err := os.WriteFile(name, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
				t.Fatalf("write executable %d: %v", i, err)
			}
		}
		_, err := collectExecutableFilesWithLimits(root, updateScanLimits{MaxURLScanFileBytes: updateMaxURLScanFileBytes, MaxScanFiles: 2})
		if err == nil || !strings.Contains(err.Error(), "executable scan exceeded max file count") {
			t.Fatalf("expected executable scan max-file error, got %v", err)
		}
	})

	t.Run("filterLockFiles and summarize", func(t *testing.T) {
		filtered := filterLockFiles([]lockFileHash{
			{Path: installReportFile},
			{Path: "README.md"},
		}, map[string]struct{}{installReportFile: {}})
		if len(filtered) != 1 || filtered[0].Path != "README.md" {
			t.Fatalf("unexpected filtered files: %+v", filtered)
		}

		risk := summarizeFindingSeverities([]inspectFinding{
			{Severity: "critical"},
			{Severity: "high"},
			{Severity: "medium"},
			{Severity: "low"},
		})
		if risk.Critical != 1 || risk.High != 1 || risk.Medium != 1 || risk.Low != 1 {
			t.Fatalf("unexpected risk summary: %+v", risk)
		}

		summary := summarizeUpdateSkills([]updateSkillItem{
			{Status: "UP_TO_DATE"},
			{Status: "CHANGED"},
			{Status: "REJECTED"},
			{Status: "SKIPPED"},
			{Status: "ERROR"},
		})
		if summary.Total != 5 || summary.UpToDate != 1 || summary.Changed != 1 || summary.Rejected != 1 || summary.Skipped != 1 || summary.Errors != 1 {
			t.Fatalf("unexpected update summary: %+v", summary)
		}

		score := computeUpdateRiskScore(
			lockFindingSummary{Critical: 1, High: 1},
			lockFindingSummary{Critical: 1, High: 2, Medium: 1},
			updateRiskSignalInputs{
				NewURLs:         2,
				NewExecutables:  1,
				FileDelta:       3,
				OverrideAdded:   1,
				OverrideRemoved: 1,
			},
		)
		if score.Model != updateRiskScoreModel {
			t.Fatalf("risk score model = %q, want %q", score.Model, updateRiskScoreModel)
		}
		if score.Previous != 125 {
			t.Fatalf("risk score previous = %d, want 125", score.Previous)
		}
		if score.Current != 194 {
			t.Fatalf("risk score current = %d, want 194", score.Current)
		}
		if score.Delta != 69 {
			t.Fatalf("risk score delta = %d, want 69", score.Delta)
		}
		if score.Signals != 37 {
			t.Fatalf("risk score signals = %d, want 37", score.Signals)
		}

		if got := cappedWeightedContribution(0, 7, 10); got != 0 {
			t.Fatalf("cappedWeightedContribution(count=0) = %d, want 0", got)
		}
		if got := cappedWeightedContribution(3, 0, 10); got != 0 {
			t.Fatalf("cappedWeightedContribution(weight=0) = %d, want 0", got)
		}
		if got := cappedWeightedContribution(3, 4, 0); got != 12 {
			t.Fatalf("cappedWeightedContribution(no cap) = %d, want 12", got)
		}
		if got := cappedWeightedContribution(10, 6, 20); got != 20 {
			t.Fatalf("cappedWeightedContribution(cap high) = %d, want 20", got)
		}
		if got := cappedWeightedContribution(10, -6, 20); got != -20 {
			t.Fatalf("cappedWeightedContribution(cap low) = %d, want -20", got)
		}
	})

	t.Run("buildUpdateReport handles non-directory entries and bad locks", func(t *testing.T) {
		targetRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(targetRoot, "README.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write file entry: %v", err)
		}
		if err := os.Mkdir(filepath.Join(targetRoot, "bad-skill"), 0o755); err != nil {
			t.Fatalf("mkdir bad skill: %v", err)
		}

		report, err := buildUpdateReport(targetRoot, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("buildUpdateReport() error = %v", err)
		}
		if report.Summary.Total != 1 || report.Summary.Errors != 1 {
			t.Fatalf("unexpected summary: %+v", report.Summary)
		}
		if report.Skills[0].Status != "ERROR" {
			t.Fatalf("expected ERROR status, got %+v", report.Skills[0])
		}
	})

	t.Run("buildUpdateReport captures source evaluation errors", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "broken-source"), 0o755); err != nil {
			t.Fatalf("mkdir broken-source: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "broken-source",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: filepath.Join(targetRoot, "missing-source"),
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "broken-source", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		report, err := buildUpdateReport(targetRoot, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("buildUpdateReport() error = %v", err)
		}
		if report.Summary.Errors != 1 {
			t.Fatalf("expected one error, got %+v", report.Summary)
		}
		if !strings.Contains(report.Skills[0].Message, "source not found") {
			t.Fatalf("expected source error message, got %+v", report.Skills[0])
		}
	})

	t.Run("buildUpdateReport infers wrapped rule_id from source evaluation errors", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mkfifo is not available on windows")
		}

		sourceRoot := createSkillSourceForInstallTest(t, "wrapped-rule-source")
		fifoPath := filepath.Join(sourceRoot, "pipe.fifo")
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo command not available")
		}
		if err := exec.Command("mkfifo", fifoPath).Run(); err != nil {
			t.Skipf("mkfifo unsupported in this environment: %v", err)
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "wrapped-rule-source"), 0o755); err != nil {
			t.Fatalf("mkdir wrapped-rule-source: %v", err)
		}
		lock := installLock{
			Schema:      "gokui.lock/v1",
			Name:        "wrapped-rule-source",
			InstalledAt: "2026-05-24T00:00:00Z",
			Source: lockSource{
				Type:  "local",
				Input: sourceRoot,
				Kind:  "local-dir",
			},
			Skill: lockSkill{
				RootSHA256: strings.Repeat("a", 64),
				Files: []lockFileHash{
					{Path: "SKILL.md", SHA256: strings.Repeat("b", 64), Bytes: 1},
				},
			},
			Policy: lockPolicy{
				Profile:  "strict",
				Decision: "pass",
			},
		}
		raw, err := json.MarshalIndent(lock, "", "  ")
		if err != nil {
			t.Fatalf("marshal lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "wrapped-rule-source", installLockFile), raw, 0o644); err != nil {
			t.Fatalf("write lock: %v", err)
		}

		report, err := buildUpdateReport(targetRoot, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("buildUpdateReport() error = %v", err)
		}
		if report.Summary.Errors != 1 {
			t.Fatalf("expected one error, got %+v", report.Summary)
		}
		if report.Skills[0].RuleID != "SPECIAL_FILE_IN_SCAN_SOURCE" {
			t.Fatalf("expected wrapped rule_id extraction, got %+v", report.Skills[0])
		}
		if !strings.Contains(report.Skills[0].Message, "failed walking skill files for scan") {
			t.Fatalf("expected wrapped source scan message, got %+v", report.Skills[0])
		}
	})

	t.Run("buildUpdateReport captures installed-tree evaluation errors", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("permission behavior differs on windows")
		}

		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(targetRoot, 0o755); err != nil {
			t.Fatalf("mkdir target root: %v", err)
		}

		src := createSkillSourceForInstallTest(t, "eval-error-skill")
		report := installReport{
			SchemaVersion: "0.1.0-draft",
			Source:        source{Input: src, Kind: "local-dir"},
			PolicyProfile: "strict",
			Decision:      "PASS",
		}
		installedPath, _, err := installSkillAtomic(src, targetRoot, "eval-error-skill", report)
		if err != nil {
			t.Fatalf("installSkillAtomic() error = %v", err)
		}
		blocked := filepath.Join(installedPath, "blocked.md")
		if err := os.WriteFile(blocked, []byte("blocked"), 0o644); err != nil {
			t.Fatalf("write blocked file: %v", err)
		}
		if err := os.Chmod(blocked, 0o000); err != nil {
			t.Fatalf("chmod blocked file: %v", err)
		}
		defer os.Chmod(blocked, 0o644)

		got, err := buildUpdateReport(targetRoot, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("buildUpdateReport() error = %v", err)
		}
		if got.Summary.Errors != 1 {
			t.Fatalf("expected one evaluation error, got %+v", got.Summary)
		}
		if got.Skills[0].ErrorCode != updateCodeEvaluationError {
			t.Fatalf("expected evaluation error code, got %+v", got.Skills[0])
		}
	})

	t.Run("buildUpdateReport sorts skill names", func(t *testing.T) {
		targetRoot := filepath.Join(t.TempDir(), "skills")
		if err := os.MkdirAll(filepath.Join(targetRoot, "z-skill"), 0o755); err != nil {
			t.Fatalf("mkdir z-skill: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(targetRoot, "a-skill"), 0o755); err != nil {
			t.Fatalf("mkdir a-skill: %v", err)
		}
		// invalid lock bytes so both entries become ERROR but still sorted.
		if err := os.WriteFile(filepath.Join(targetRoot, "z-skill", installLockFile), []byte("{"), 0o644); err != nil {
			t.Fatalf("write z lock: %v", err)
		}
		if err := os.WriteFile(filepath.Join(targetRoot, "a-skill", installLockFile), []byte("{"), 0o644); err != nil {
			t.Fatalf("write a lock: %v", err)
		}

		report, err := buildUpdateReport(targetRoot, false, policypkg.Config{})
		if err != nil {
			t.Fatalf("buildUpdateReport() error = %v", err)
		}
		if len(report.Skills) != 2 {
			t.Fatalf("expected 2 skills, got %d", len(report.Skills))
		}
		if report.Skills[0].Name != "a-skill" || report.Skills[1].Name != "z-skill" {
			t.Fatalf("expected sorted skills, got %+v", report.Skills)
		}
	})
}

type errorReader struct {
	err error
}

func (r errorReader) Read(_ []byte) (int, error) {
	return 0, r.err
}
