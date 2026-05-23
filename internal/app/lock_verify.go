package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type lockVerifyArgs struct {
	Path   string
	Format string
}

type lockVerifyReport struct {
	SchemaVersion string              `json:"schema_version"`
	SkillPath     string              `json:"skill_path"`
	Status        string              `json:"status"`
	Checks        []lockVerifyCheck   `json:"checks"`
	Drift         lockVerifyDriftInfo `json:"drift"`
	Note          string              `json:"note"`
}

type lockVerifyCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type lockVerifyDriftInfo struct {
	MissingFiles    []string `json:"missing_files"`
	ChangedFiles    []string `json:"changed_files"`
	UnexpectedFiles []string `json:"unexpected_files"`
}

func runLockVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	parsed, err := parseLockVerifyArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	report, verifyErr := verifyLock(parsed.Path)
	if verifyErr != nil {
		_, _ = fmt.Fprintln(stderr, verifyErr.Error())
		return 1
	}

	if parsed.Format == "json" {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render lock verify report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else {
		_, _ = fmt.Fprintln(stdout, "gokui lock verify report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "path: %s\n", report.SkillPath)
		_, _ = fmt.Fprintf(stdout, "status: %s\n", report.Status)
		for _, check := range report.Checks {
			state := "ok"
			if !check.OK {
				state = "failed"
			}
			_, _ = fmt.Fprintf(stdout, "- %s: %s (%s)\n", check.Name, state, check.Detail)
		}
		if len(report.Drift.MissingFiles) > 0 {
			_, _ = fmt.Fprintf(stdout, "missing: %s\n", strings.Join(report.Drift.MissingFiles, ", "))
		}
		if len(report.Drift.ChangedFiles) > 0 {
			_, _ = fmt.Fprintf(stdout, "changed: %s\n", strings.Join(report.Drift.ChangedFiles, ", "))
		}
		if len(report.Drift.UnexpectedFiles) > 0 {
			_, _ = fmt.Fprintf(stdout, "unexpected: %s\n", strings.Join(report.Drift.UnexpectedFiles, ", "))
		}
	}

	if report.Status == "VERIFIED" {
		return 0
	}
	return 2
}

func parseLockVerifyArgs(args []string) (lockVerifyArgs, error) {
	out := lockVerifyArgs{
		Path:   ".",
		Format: "human",
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				return lockVerifyArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return lockVerifyArgs{}, fmt.Errorf("unknown lock verify option: %s", arg)
		default:
			if out.Path != "." {
				return lockVerifyArgs{}, fmt.Errorf("lock verify accepts at most one path")
			}
			out.Path = arg
		}
	}
	if out.Format != "human" && out.Format != "json" {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}

func verifyLock(skillPath string) (lockVerifyReport, error) {
	cleanPath := filepath.Clean(skillPath)
	lockPath := filepath.Join(cleanPath, installLockFile)
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		return lockVerifyReport{}, fmt.Errorf("failed to read lockfile: %s", lockPath)
	}

	var lock installLock
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		return lockVerifyReport{}, fmt.Errorf("invalid lockfile JSON: %s", lockPath)
	}

	checks := make([]lockVerifyCheck, 0, 6)
	schemaOK := lock.Schema == "gokui.lock/v1"
	checks = append(checks, lockVerifyCheck{
		Name:   "schema",
		OK:     schemaOK,
		Detail: fmt.Sprintf("expected gokui.lock/v1, got %s", lock.Schema),
	})

	nameOK := lock.Name == filepath.Base(cleanPath)
	checks = append(checks, lockVerifyCheck{
		Name:   "name",
		OK:     nameOK,
		Detail: fmt.Sprintf("expected %s, got %s", filepath.Base(cleanPath), lock.Name),
	})

	sourceOK, sourceDetail := verifyLockSource(lock)
	checks = append(checks, lockVerifyCheck{
		Name:   "source",
		OK:     sourceOK,
		Detail: sourceDetail,
	})
	sourceMetaOK, sourceMetaDetail := verifyLockSourceMetadata(cleanPath, lock)
	checks = append(checks, lockVerifyCheck{
		Name:   "source_metadata",
		OK:     sourceMetaOK,
		Detail: sourceMetaDetail,
	})

	actualFiles, actualRootHash, err := buildFileDigestsForLock(cleanPath)
	if err != nil {
		return lockVerifyReport{}, err
	}

	missing, changed, unexpected := diffLockFiles(lock.Skill.Files, actualFiles)
	digestOK := len(missing) == 0 && len(changed) == 0 && len(unexpected) == 0
	checks = append(checks, lockVerifyCheck{
		Name:   "file_digests",
		OK:     digestOK,
		Detail: fmt.Sprintf("missing=%d changed=%d unexpected=%d", len(missing), len(changed), len(unexpected)),
	})

	rootOK := lock.Skill.RootSHA256 == actualRootHash
	checks = append(checks, lockVerifyCheck{
		Name:   "root_hash",
		OK:     rootOK,
		Detail: fmt.Sprintf("expected %s, got %s", lock.Skill.RootSHA256, actualRootHash),
	})

	status := "VERIFIED"
	for _, check := range checks {
		if !check.OK {
			status = "DRIFTED"
			break
		}
	}

	return lockVerifyReport{
		SchemaVersion: "0.1.0-draft",
		SkillPath:     cleanPath,
		Status:        status,
		Checks:        checks,
		Drift: lockVerifyDriftInfo{
			MissingFiles:    missing,
			ChangedFiles:    changed,
			UnexpectedFiles: unexpected,
		},
		Note: "pre-release lock verify checks installed file integrity against gokui.lock",
	}, nil
}

func diffLockFiles(expected []lockFileHash, actual []lockFileHash) (missing []string, changed []string, unexpected []string) {
	expectedMap := make(map[string]lockFileHash, len(expected))
	for _, file := range expected {
		expectedMap[file.Path] = file
	}

	actualMap := make(map[string]lockFileHash, len(actual))
	for _, file := range actual {
		actualMap[file.Path] = file
	}

	for path, exp := range expectedMap {
		act, ok := actualMap[path]
		if !ok {
			missing = append(missing, path)
			continue
		}
		if exp.SHA256 != act.SHA256 || exp.Bytes != act.Bytes {
			changed = append(changed, path)
		}
	}
	for path := range actualMap {
		if _, ok := expectedMap[path]; !ok {
			unexpected = append(unexpected, path)
		}
	}

	sort.Strings(missing)
	sort.Strings(changed)
	sort.Strings(unexpected)
	return missing, changed, unexpected
}

func verifyLockSource(lock installLock) (bool, string) {
	if strings.TrimSpace(lock.Source.Kind) == "" {
		return false, "lock source kind is empty"
	}
	if strings.TrimSpace(lock.Source.Input) == "" {
		return false, "lock source input is empty"
	}

	expectedType := sourceTypeFromKind(lock.Source.Kind)
	if expectedType == "unknown" {
		return false, fmt.Sprintf("unsupported lock source kind: %s", lock.Source.Kind)
	}
	if lock.Source.Type != expectedType {
		return false, fmt.Sprintf("source type mismatch for kind %s: expected %s, got %s", lock.Source.Kind, expectedType, lock.Source.Type)
	}

	if lock.Source.Kind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(lock.Source.Input)
		if err != nil {
			return false, fmt.Sprintf("invalid github source input in lock: %v", err)
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return false, "github lock source must be commit-pinned"
		}
	}
	return true, fmt.Sprintf("kind=%s type=%s", lock.Source.Kind, lock.Source.Type)
}

func verifyLockSourceMetadata(skillPath string, lock installLock) (bool, string) {
	if lock.Source.Kind != "github-source" {
		return true, fmt.Sprintf("not required for source kind %s", lock.Source.Kind)
	}

	err := verifyInstalledSourceMetadata(skillPath, source{
		Input: lock.Source.Input,
		Kind:  lock.Source.Kind,
	})
	if err != nil {
		return false, err.Error()
	}
	return true, "metadata matches lock source and installed hash"
}
