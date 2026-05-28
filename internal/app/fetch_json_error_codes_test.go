package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rulepkg "github.com/watany-dev/gokui/internal/rule"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

func TestRunFetchJSONErrorCodes(t *testing.T) {
	t.Run("json mode failure codes cover major branches", func(t *testing.T) {
		sourceDir := createSkillSourceForInstallTest(t, "json-error-skill")
		var stdout strings.Builder
		var stderr strings.Builder

		// invalid source syntax
		code := runFetch([]string{"github:org/repo/path@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// uppercase commit sha
		code = runFetch([]string{"github:org/repo//skills/x@8F3C2D1A4B5C6D7E8F901234567890ABCDEF1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for uppercase sha, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// control character in source
		code = runFetch([]string{"github:org/repo//skills/x@\n8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for control-char source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "must not contain C0/C1 control characters") {
			t.Fatalf("expected control-character detail in json error, got stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// C1 control character in source
		code = runFetch([]string{"github:org/repo//skills/x@\u00858f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for C1 control source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "must not contain C0/C1 control characters") {
			t.Fatalf("expected C1 control-character detail in json error, got stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// invalid UTF-8 in source
		invalidUTF8Source := string([]byte("github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234\xff"))
		code = runFetch([]string{invalidUTF8Source, "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for invalid UTF-8 source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "must be valid UTF-8") {
			t.Fatalf("expected UTF-8 validation detail in json error, got stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// surrounding whitespace in path
		code = runFetch([]string{"github:org/repo// skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for path-space source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// non-canonical path segments
		code = runFetch([]string{"github:org/repo//skills//x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
			t.Fatalf("expected source invalid code for non-canonical path source, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		unicodeThreatSources := []struct {
			name   string
			source string
		}{
			{
				name:   "owner unicode whitespace",
				source: "github:or\u00a0g/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			},
			{
				name:   "repo zero-width",
				source: "github:org/re\u200bpo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234",
			},
			{
				name:   "ref unicode tag",
				source: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\U000E00011234567890abcdef1234",
			},
			{
				name:   "ref variation selector",
				source: "github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f90\ufe0f1234567890abcdef1234",
			},
		}
		for _, tc := range unicodeThreatSources {
			code = runFetch([]string{tc.source, "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
			if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceInvalid) {
				t.Fatalf("expected source invalid code for %s, got code=%d stdout=%q stderr=%q", tc.name, code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "\"rule_id\":") {
				t.Fatalf("stdout should omit rule_id for non-rule source invalid (%s), got %q", tc.name, stdout.String())
			}
			stdout.Reset()
			stderr.Reset()
		}

		// floating ref
		code = runFetch([]string{"github:org/repo//skills/x@main", "--out", t.TempDir(), "--format", "json"}, &stdout, &stderr)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceRefNotPinned) {
			t.Fatalf("expected ref-not-pinned code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source download/materialize failure
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return "", nil, errors.New("download failed")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source download/materialize failure with rule-prefixed error
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return "", nil, errors.New("ARCHIVE_PATH_ESCAPE: archive entry escaped source root")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code for rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"ARCHIVE_PATH_ESCAPE\"") {
			t.Fatalf("stdout should include source download rule_id, got %q", stdout.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source download/materialize failure with https rule-prefixed error
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return "", nil, errors.New("GITHUB_ARCHIVE_SCHEME_INVALID: github archive URL must use https")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSourceDownloadFailed) {
			t.Fatalf("expected source-download-failed code for https rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \"GITHUB_ARCHIVE_SCHEME_INVALID\"") {
			t.Fatalf("stdout should include https rule_id, got %q", stdout.String())
		}
		stdout.Reset()
		stderr.Reset()

		// invalid skill frontmatter
		badSkill := t.TempDir()
		if err := os.WriteFile(filepath.Join(badSkill, "SKILL.md"), []byte("# bad"), 0o644); err != nil {
			t.Fatalf("write bad SKILL.md: %v", err)
		}
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/x@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return badSkill, nil, nil
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeSkillInvalid) {
			t.Fatalf("expected skill-invalid code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// output prepare failure
		outFile := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(outFile, []byte("x"), 0o644); err != nil {
			t.Fatalf("write out file: %v", err)
		}
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", filepath.Join(outFile, "child"), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeOutputPrepareFailed) {
			t.Fatalf("expected output-prepare-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// copy failure
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				FetchSkillAtomic: func(skillRoot string, outRoot string, skillName string) (string, error) {
					return "", errors.New("copy failed")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeCopyFailed) {
			t.Fatalf("expected copy-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// digest failure
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				FetchSkillAtomic: func(skillRoot string, outRoot string, skillName string) (string, error) {
					return filepath.Join(outRoot, "missing-after-copy"), nil
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeDigestFailed) {
			t.Fatalf("expected digest-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source metadata write failure
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				WriteSourceMetadata: func(skillRoot string, meta sourceMetadata) error {
					return errors.New("meta write failed")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeMetadataWriteFailed) {
			t.Fatalf("expected metadata-write-failed code, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		stdout.Reset()
		stderr.Reset()

		// source metadata write failure with rule-prefixed error
		code = runFetchWithDeps(
			[]string{"github:org/repo//skills/json-error-skill@8f3c2d1a4b5c6d7e8f901234567890abcdef1234", "--out", t.TempDir(), "--format", "json"},
			&stdout,
			&stderr,
			fetchDeps{
				FetchGitHubSkill: func(spec srcpkg.GitHubSpec) (string, func(), error) {
					return sourceDir, nil, nil
				},
				WriteSourceMetadata: func(skillRoot string, meta sourceMetadata) error {
					return errors.New(rulepkg.SourceMetadataSymlink.ID + ": source metadata file must not be a symlink")
				},
			},
		)
		if code != 1 || !strings.Contains(stdout.String(), fetchErrorCodeMetadataWriteFailed) {
			t.Fatalf("expected metadata-write-failed code for rule-prefixed error, got code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "\"rule_id\": \""+rulepkg.SourceMetadataSymlink.ID+"\"") {
			t.Fatalf("stdout should include metadata-write rule_id, got %q", stdout.String())
		}
	})

}
