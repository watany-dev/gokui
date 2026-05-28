package app

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	"github.com/watany-dev/gokui/internal/limitio"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	"github.com/watany-dev/gokui/internal/safefs"
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

type lockVerifyErrorReport struct {
	SchemaVersion string `json:"schema_version"`
	SkillPath     string `json:"skill_path"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code"`
	RuleID        string `json:"rule_id,omitempty"`
	Message       string `json:"message"`
	Note          string `json:"note"`
}

type lockVerifyCheck struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

var (
	maxLockVerifyLockFileBytes int64 = 1_000_000
	maxInstallReportFileBytes  int64 = 1_000_000
	errLockfileReadFailed            = errors.New("failed to read lockfile")
	errLockfileInvalidJSON           = errors.New("invalid lockfile JSON")
)

const (
	lockVerifyCodeSchema         = "LOCK_SCHEMA"
	lockVerifyCodeName           = "SKILL_NAME"
	lockVerifyCodeStructure      = "LOCK_STRUCTURE"
	lockVerifyCodeSource         = "LOCK_SOURCE"
	lockVerifyCodeSourceMetadata = "SOURCE_METADATA"
	lockVerifyCodeInstallReport  = "INSTALL_REPORT"
	lockVerifyCodeFileDigests    = "FILE_DIGESTS"
	lockVerifyCodeRootHash       = "ROOT_HASH"
)

const (
	lockVerifyErrorCodeArgsInvalid     = "LOCK_VERIFY_ARGS_INVALID"
	lockVerifyErrorCodeReadLockfile    = "LOCKFILE_READ_FAILED"
	lockVerifyErrorCodeInvalidLockfile = "LOCKFILE_INVALID_JSON"
	lockVerifyErrorCodeDigestFailed    = "FILE_DIGEST_BUILD_FAILED"
	lockVerifyErrorCodeUnknown         = "LOCK_VERIFY_FAILED"
)

type lockVerifyDriftInfo struct {
	MissingFiles    []string `json:"missing_files"`
	ChangedFiles    []string `json:"changed_files"`
	UnexpectedFiles []string `json:"unexpected_files"`
}

type fileInfoStatter = limitio.FileInfoStatter

func runLockVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	parsed, err := parseLockVerifyArgs(args)
	if err != nil {
		if requestedJSON {
			return writeLockVerifyJSONError(stdout, stderr, lockVerifyErrorReport{
				SchemaVersion: reportSchemaVersion,
				SkillPath:     extractLockVerifyPathArg(args),
				Status:        reportStatusError,
				ErrorCode:     lockVerifyErrorCodeArgsInvalid,
				Message:       err.Error(),
				Note:          "lock verify failed before path validation",
			})
		}
		if requestedSARIF {
			return writeLockVerifySARIFError(stdout, stderr, lockVerifyErrorReport{
				SchemaVersion: reportSchemaVersion,
				SkillPath:     extractLockVerifyPathArg(args),
				Status:        reportStatusError,
				ErrorCode:     lockVerifyErrorCodeArgsInvalid,
				Message:       err.Error(),
				Note:          "lock verify failed before path validation",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}

	report, verifyErr := verifyLock(parsed.Path)
	if verifyErr != nil {
		errorReport := lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     filepath.Clean(parsed.Path),
			Status:        reportStatusError,
			ErrorCode:     classifyLockVerifyError(verifyErr),
			Message:       verifyErr.Error(),
			Note:          "lock verify failed before producing drift report",
		}
		if parsed.Format == "json" {
			return writeLockVerifyJSONError(stdout, stderr, errorReport)
		}
		if parsed.Format == "sarif" {
			return writeLockVerifySARIFError(stdout, stderr, errorReport)
		}
		_, _ = fmt.Fprintln(stderr, verifyErr.Error())
		return exitcode.Error.Int()
	}

	if parsed.Format == "json" {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render lock verify report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if parsed.Format == "sarif" {
		out, err := json.MarshalIndent(buildLockVerifySARIFReport(report), "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render lock verify sarif report")
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if parsed.Format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildLockVerifyCompactSummary(report))
	} else {
		_, _ = fmt.Fprintln(stdout, "gokui lock verify report (pre-release)")
		_, _ = fmt.Fprintf(stdout, "path: %s\n", report.SkillPath)
		_, _ = fmt.Fprintf(stdout, "status: %s\n", report.Status)
		for _, check := range report.Checks {
			state := "ok"
			if !check.OK {
				state = "failed"
			}
			_, _ = fmt.Fprintf(stdout, "- %s [%s]: %s (%s)\n", check.Name, check.Code, state, check.Detail)
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
		return exitcode.OK.Int()
	}
	return exitcode.Rejected.Int()
}

func verifyLock(skillPath string) (lockVerifyReport, error) {
	cleanPath := filepath.Clean(skillPath)
	if err := rejectSymlinkPath(cleanPath, "lock verify path", rulepkg.LockVerifyPathSymlink.ID); err != nil {
		return lockVerifyReport{}, err
	}
	lockPath := filepath.Join(cleanPath, installLockFile)
	linkInfo, lstatErr := os.Lstat(lockPath)
	if lstatErr != nil {
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (symlink is not allowed): %s", rulepkg.LockfileSymlink.ID, errLockfileReadFailed, lockPath)
	}
	if !linkInfo.Mode().IsRegular() {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (regular file required): %s", rulepkg.LockfileSpecialFile.ID, errLockfileReadFailed, lockPath)
	}

	f, err := os.Open(lockPath)
	if err != nil {
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	defer f.Close()
	if err := ensureLockfileStableFromOpen(linkInfo, f, lockPath); err != nil {
		return lockVerifyReport{}, err
	}
	var lockRaw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&lockRaw, f, maxLockVerifyLockFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return lockVerifyReport{}, fmt.Errorf("%s: %w (size exceeds limit): %s", rulepkg.LockfileTooLarge.ID, errLockfileReadFailed, lockPath)
		}
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	if !utf8.Valid(lockRaw.Bytes()) {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (must be valid UTF-8): %s", rulepkg.LockfileInvalidUTF8.ID, errLockfileInvalidJSON, lockPath)
	}

	var lock installLock
	if err := json.Unmarshal(lockRaw.Bytes(), &lock); err != nil {
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileInvalidJSON, lockPath)
	}

	checks := make([]lockVerifyCheck, 0, 8)
	schemaOK := lock.Schema == lockSchemaVersion
	schemaDetail := fmt.Sprintf("expected gokui.lock/v1, got %s", lock.Schema)
	if strings.IndexFunc(lock.Schema, isC0OrC1ControlRune) >= 0 {
		schemaDetail = "lock schema must not contain C0/C1 control characters"
	} else if containsSeverityOverrideDisallowedUnicode(lock.Schema) {
		schemaDetail = "lock schema must not contain Unicode bidi, zero-width, tag, or variation-selector characters"
	} else if strings.TrimSpace(lock.Schema) != lock.Schema {
		schemaDetail = "lock schema must not contain leading or trailing whitespace"
	}
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeSchema,
		Name:   "schema",
		OK:     schemaOK,
		Detail: schemaDetail,
	})

	nameOK := lock.Name == filepath.Base(cleanPath)
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeName,
		Name:   "name",
		OK:     nameOK,
		Detail: fmt.Sprintf("expected %s, got %s", filepath.Base(cleanPath), lock.Name),
	})
	lockStructureOK, lockStructureDetail := verifyLockStructure(lock)
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeStructure,
		Name:   "lock_structure",
		OK:     lockStructureOK,
		Detail: lockStructureDetail,
	})

	sourceOK, sourceDetail := verifyLockSource(lock)
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeSource,
		Name:   "source",
		OK:     sourceOK,
		Detail: sourceDetail,
	})
	sourceMetaOK, sourceMetaDetail := verifyLockSourceMetadata(cleanPath, lock)
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeSourceMetadata,
		Name:   "source_metadata",
		OK:     sourceMetaOK,
		Detail: sourceMetaDetail,
	})
	reportOK, reportDetail := verifyInstallReport(cleanPath, lock)
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeInstallReport,
		Name:   "install_report",
		OK:     reportOK,
		Detail: reportDetail,
	})

	actualFiles, actualRootHash, err := buildFileDigestsForLock(cleanPath)
	if err != nil {
		return lockVerifyReport{}, err
	}

	missing, changed, unexpected := diffLockFiles(lock.Skill.Files, actualFiles)
	digestOK := len(missing) == 0 && len(changed) == 0 && len(unexpected) == 0
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeFileDigests,
		Name:   "file_digests",
		OK:     digestOK,
		Detail: fmt.Sprintf("missing=%d changed=%d unexpected=%d", len(missing), len(changed), len(unexpected)),
	})

	rootOK := lock.Skill.RootSHA256 == actualRootHash
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeRootHash,
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
		SchemaVersion: reportSchemaVersion,
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

func classifyLockVerifyError(err error) string {
	switch {
	case errors.Is(err, errLockfileReadFailed):
		return lockVerifyErrorCodeReadLockfile
	case errors.Is(err, errLockfileInvalidJSON):
		return lockVerifyErrorCodeInvalidLockfile
	case errors.Is(err, errDigestBuildFailed):
		return lockVerifyErrorCodeDigestFailed
	default:
		return lockVerifyErrorCodeUnknown
	}
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

func ensureLockfileStableFromOpen(previous os.FileInfo, opened fileInfoStatter, lockPath string) error {
	return safefs.Sentinel{
		Previous: previous,
		Path:     lockPath,
		StatError: func(path string) error {
			return fmt.Errorf("%w: %s", errLockfileReadFailed, path)
		},
		ChangedError: func(path string) error {
			return fmt.Errorf("%s: %w (file changed during read): %s", rulepkg.LockfileSourceChangedDuringRead.ID, errLockfileReadFailed, path)
		},
	}.CheckOpened(opened)
}

func isCanonicalSHA256Hex(in string) bool {
	if strings.TrimSpace(in) != in {
		return false
	}
	if strings.ToLower(in) != in {
		return false
	}
	decoded, err := hex.DecodeString(in)
	return err == nil && len(decoded) == 32
}

func isValidLockRelativePath(in string) bool {
	trimmed := strings.TrimSpace(in)
	if !utf8.ValidString(in) {
		return false
	}
	if strings.IndexFunc(in, isC0OrC1ControlRune) >= 0 {
		return false
	}
	if containsSeverityOverrideDisallowedUnicode(in) {
		return false
	}
	if trimmed == "" {
		return false
	}
	if trimmed != in {
		return false
	}
	if strings.Contains(in, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(in))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return false
	}
	if strings.HasPrefix(cleaned, "/") {
		return false
	}
	if safefs.HasWindowsDrivePathPrefix(cleaned) {
		return false
	}
	return cleaned == in
}

func isC0OrC1ControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1f) || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

func containsSeverityOverrideDisallowedUnicode(s string) bool {
	for _, r := range s {
		switch {
		case r >= 0x202a && r <= 0x202e:
			return true
		case r >= 0x2066 && r <= 0x2069:
			return true
		case r >= 0x200b && r <= 0x200f:
			return true
		case r >= 0xfe00 && r <= 0xfe0f:
			return true
		case r >= 0xe0100 && r <= 0xe01ef:
			return true
		case r >= 0xe0000 && r <= 0xe007f:
			return true
		case unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return true
		}
	}
	return false
}

func validateLockFindingSummary(summary lockFindingSummary) error {
	if summary.Critical < 0 {
		return fmt.Errorf("critical count must be >= 0")
	}
	if summary.High < 0 {
		return fmt.Errorf("high count must be >= 0")
	}
	if summary.Medium < 0 {
		return fmt.Errorf("medium count must be >= 0")
	}
	if summary.Low < 0 {
		return fmt.Errorf("low count must be >= 0")
	}
	return nil
}
