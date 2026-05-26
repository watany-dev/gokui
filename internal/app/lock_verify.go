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
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
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

var severityOverrideRuleIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

const ruleInstallReportTooLarge = "INSTALL_REPORT_TOO_LARGE"
const ruleInstallReportInvalidUTF8 = "INSTALL_REPORT_INVALID_UTF8"
const ruleInstallReportSymlink = "INSTALL_REPORT_SYMLINK_DETECTED"
const ruleInstallReportSpecialFile = "INSTALL_REPORT_SPECIAL_FILE"
const ruleInstallReportSourceChanged = "INSTALL_REPORT_SOURCE_CHANGED_DURING_READ"
const ruleLockVerifyPathSymlink = "LOCK_VERIFY_PATH_SYMLINK_DETECTED"
const ruleLockfileSourceChanged = "LOCKFILE_SOURCE_CHANGED_DURING_READ"

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

type fileInfoStatter interface {
	Stat() (os.FileInfo, error)
}

func runLockVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := lockVerifyArgsRequestJSON(args)
	requestedSARIF := lockVerifyArgsRequestSARIF(args)
	parsed, err := parseLockVerifyArgs(args)
	if err != nil {
		if requestedJSON {
			return writeLockVerifyJSONError(stdout, stderr, lockVerifyErrorReport{
				SchemaVersion: reportSchemaVersion,
				SkillPath:     extractLockVerifyPathArg(args),
				Status:        "ERROR",
				ErrorCode:     lockVerifyErrorCodeArgsInvalid,
				Message:       err.Error(),
				Note:          "lock verify failed before path validation",
			})
		}
		if requestedSARIF {
			return writeLockVerifySARIFError(stdout, stderr, lockVerifyErrorReport{
				SchemaVersion: reportSchemaVersion,
				SkillPath:     extractLockVerifyPathArg(args),
				Status:        "ERROR",
				ErrorCode:     lockVerifyErrorCodeArgsInvalid,
				Message:       err.Error(),
				Note:          "lock verify failed before path validation",
			})
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return 1
	}

	report, verifyErr := verifyLock(parsed.Path)
	if verifyErr != nil {
		errorReport := lockVerifyErrorReport{
			SchemaVersion: reportSchemaVersion,
			SkillPath:     filepath.Clean(parsed.Path),
			Status:        "ERROR",
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
		return 1
	}

	if parsed.Format == "json" {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render lock verify report")
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
	} else if parsed.Format == "sarif" {
		out, err := json.MarshalIndent(buildLockVerifySARIFReport(report), "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "failed to render lock verify sarif report")
			return 1
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
		return 0
	}
	return 2
}

func lockVerifyArgsRequestJSON(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == "json" {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == "json" {
			return true
		}
	}
	return false
}

func lockVerifyArgsRequestSARIF(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) && args[i+1] == "sarif" {
			return true
		}
		if strings.HasPrefix(args[i], "--format=") && strings.TrimPrefix(args[i], "--format=") == "sarif" {
			return true
		}
	}
	return false
}

func extractLockVerifyPathArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--format" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return "."
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
	if out.Format != "human" && out.Format != "json" && out.Format != "sarif" && out.Format != "compact" {
		return lockVerifyArgs{}, fmt.Errorf("unsupported lock verify format: %s", out.Format)
	}
	return out, nil
}

func buildLockVerifyCompactSummary(report lockVerifyReport) string {
	failed := 0
	for _, check := range report.Checks {
		if !check.OK {
			failed++
		}
	}
	return fmt.Sprintf(
		"lock_verify status=%s checks=%d failed=%d missing=%d changed=%d unexpected=%d path=%q",
		report.Status,
		len(report.Checks),
		failed,
		len(report.Drift.MissingFiles),
		len(report.Drift.ChangedFiles),
		len(report.Drift.UnexpectedFiles),
		report.SkillPath,
	)
}

func buildLockVerifySARIFReport(report lockVerifyReport) inspectSARIFReport {
	decision := "PASS"
	if report.Status != "VERIFIED" {
		decision = "DRIFTED"
	}

	rules := make([]inspectSARIFRule, 0, len(report.Checks))
	for _, check := range report.Checks {
		rules = append(rules, inspectSARIFRule{
			ID: check.Code,
			ShortDescription: inspectSARIFMessageContainer{
				Text: fmt.Sprintf("lock verify check: %s", check.Name),
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	results := make([]inspectSARIFResult, 0, 32)
	for _, check := range report.Checks {
		if check.OK {
			continue
		}
		results = append(results, inspectSARIFResult{
			RuleID:  check.Code,
			Level:   "error",
			Message: inspectSARIFMessageContainer{Text: check.Detail},
		})
		if check.Code != lockVerifyCodeFileDigests {
			continue
		}
		for _, path := range report.Drift.MissingFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "missing file listed in lock"))
		}
		for _, path := range report.Drift.ChangedFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "changed file hash or size"))
		}
		for _, path := range report.Drift.UnexpectedFiles {
			results = append(results, lockVerifyDriftSARIFResult(check.Code, path, "unexpected file not listed in lock"))
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		uriI := ""
		if len(results[i].Locations) > 0 {
			uriI = results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		uriJ := ""
		if len(results[j].Locations) > 0 {
			uriJ = results[j].Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		if uriI != uriJ {
			return uriI < uriJ
		}
		return results[i].Message.Text < results[j].Message.Text
	})

	return inspectSARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []inspectSARIFRun{
			{
				Tool: inspectSARIFTool{
					Driver: inspectSARIFDriver{
						Name:    "gokui",
						Version: "pre-release",
						Rules:   rules,
					},
				},
				Results: results,
				Invocations: []inspectSARIFInvocation{
					{ExecutionSuccessful: report.Status == "VERIFIED"},
				},
				Properties: inspectSARIFProperties{
					SchemaVersion: report.SchemaVersion,
					PreRelease:    true,
					SourceInput:   report.SkillPath,
					SourceKind:    "installed-skill",
					Decision:      decision,
					Note:          report.Note,
				},
			},
		},
	}
}

func lockVerifyDriftSARIFResult(ruleID string, path string, reason string) inspectSARIFResult {
	result := inspectSARIFResult{
		RuleID:  ruleID,
		Level:   "error",
		Message: inspectSARIFMessageContainer{Text: fmt.Sprintf("%s: %s", reason, path)},
	}
	if strings.TrimSpace(path) == "" {
		return result
	}
	result.Locations = []inspectSARIFLocation{
		{
			PhysicalLocation: inspectSARIFPhysicalLocation{
				ArtifactLocation: inspectSARIFArtifactLocation{
					URI: path,
				},
			},
		},
	}
	return result
}

func writeLockVerifyJSONError(stdout io.Writer, stderr io.Writer, report lockVerifyErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, lockVerifyErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render lock verify error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func writeLockVerifySARIFError(stdout io.Writer, stderr io.Writer, report lockVerifyErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, lockVerifyErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(buildLockVerifySARIFErrorReport(report), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render lock verify sarif error report")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return 1
}

func buildLockVerifySARIFErrorReport(report lockVerifyErrorReport) inspectSARIFReport {
	ruleID := report.ErrorCode
	if report.RuleID != "" {
		ruleID = report.RuleID
	}
	return inspectSARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []inspectSARIFRun{
			{
				Tool: inspectSARIFTool{
					Driver: inspectSARIFDriver{
						Name:    "gokui",
						Version: "pre-release",
						Rules: []inspectSARIFRule{
							{
								ID: ruleID,
								ShortDescription: inspectSARIFMessageContainer{
									Text: report.ErrorCode,
								},
							},
						},
					},
				},
				Results: []inspectSARIFResult{
					{
						RuleID:  ruleID,
						Level:   "error",
						Message: inspectSARIFMessageContainer{Text: report.Message},
					},
				},
				Invocations: []inspectSARIFInvocation{
					{ExecutionSuccessful: false},
				},
				Properties: inspectSARIFProperties{
					SchemaVersion: report.SchemaVersion,
					PreRelease:    true,
					SourceInput:   report.SkillPath,
					SourceKind:    "installed-skill",
					Decision:      report.Status,
					Note:          fmt.Sprintf("%s; error_code=%s", report.Note, report.ErrorCode),
				},
			},
		},
	}
}

func verifyLock(skillPath string) (lockVerifyReport, error) {
	cleanPath := filepath.Clean(skillPath)
	if err := rejectSymlinkPath(cleanPath, "lock verify path", ruleLockVerifyPathSymlink); err != nil {
		return lockVerifyReport{}, err
	}
	lockPath := filepath.Join(cleanPath, installLockFile)
	linkInfo, lstatErr := os.Lstat(lockPath)
	if lstatErr != nil {
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (symlink is not allowed): %s", ruleLockfileSymlink, errLockfileReadFailed, lockPath)
	}
	if !linkInfo.Mode().IsRegular() {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (regular file required): %s", ruleLockfileSpecialFile, errLockfileReadFailed, lockPath)
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
			return lockVerifyReport{}, fmt.Errorf("%s: %w (size exceeds limit): %s", ruleLockfileTooLarge, errLockfileReadFailed, lockPath)
		}
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	if !utf8.Valid(lockRaw.Bytes()) {
		return lockVerifyReport{}, fmt.Errorf("%s: %w (must be valid UTF-8): %s", ruleLockfileInvalidUTF8, errLockfileInvalidJSON, lockPath)
	}

	var lock installLock
	if err := json.Unmarshal(lockRaw.Bytes(), &lock); err != nil {
		return lockVerifyReport{}, fmt.Errorf("%w: %s", errLockfileInvalidJSON, lockPath)
	}

	checks := make([]lockVerifyCheck, 0, 8)
	schemaOK := lock.Schema == lockSchemaVersion
	checks = append(checks, lockVerifyCheck{
		Code:   lockVerifyCodeSchema,
		Name:   "schema",
		OK:     schemaOK,
		Detail: fmt.Sprintf("expected gokui.lock/v1, got %s", lock.Schema),
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

func verifyLockSource(lock installLock) (bool, string) {
	trimmedKind := strings.TrimSpace(lock.Source.Kind)
	if trimmedKind == "" {
		return false, "lock source kind is empty"
	}
	if trimmedKind != lock.Source.Kind {
		return false, "lock source kind must not contain leading or trailing whitespace"
	}
	if strings.IndexFunc(trimmedKind, isC0OrC1ControlRune) >= 0 {
		return false, "lock source kind must not contain C0/C1 control characters"
	}
	if trimmedKind != strings.ToLower(trimmedKind) {
		return false, "lock source kind must be canonical lowercase"
	}
	trimmedInput := strings.TrimSpace(lock.Source.Input)
	if trimmedInput == "" {
		return false, "lock source input is empty"
	}
	if trimmedInput != lock.Source.Input {
		return false, "lock source input must not contain leading or trailing whitespace"
	}
	if strings.IndexFunc(trimmedInput, isC0OrC1ControlRune) >= 0 {
		return false, "lock source input must not contain C0/C1 control characters"
	}
	detectedKind := detectSourceKind(trimmedInput)
	if trimmedKind != detectedKind {
		return false, fmt.Sprintf("lock source kind does not match source input: kind=%s detected=%s", trimmedKind, detectedKind)
	}

	expectedType := sourceTypeFromKind(trimmedKind)
	if expectedType == "unknown" {
		return false, fmt.Sprintf("unsupported lock source kind: %s", trimmedKind)
	}
	if expectedType != "github" {
		cleanedInput := filepath.Clean(trimmedInput)
		if trimmedInput != cleanedInput {
			return false, "lock source input must be a canonical cleaned path for local/archive sources"
		}
	}
	trimmedType := strings.TrimSpace(lock.Source.Type)
	if trimmedType != lock.Source.Type {
		return false, "lock source type must not contain leading or trailing whitespace"
	}
	if strings.IndexFunc(trimmedType, isC0OrC1ControlRune) >= 0 {
		return false, "lock source type must not contain C0/C1 control characters"
	}
	if trimmedType != strings.ToLower(trimmedType) {
		return false, "lock source type must be canonical lowercase"
	}
	if trimmedType != expectedType {
		return false, fmt.Sprintf("source type mismatch for kind %s: expected %s, got %s", trimmedKind, expectedType, trimmedType)
	}

	if trimmedKind == "github-source" {
		spec, err := srcpkg.ParseGitHubSource(trimmedInput)
		if err != nil {
			return false, fmt.Sprintf("invalid github source input in lock: %v", err)
		}
		if trimmedInput != canonicalGitHubSourceInput(spec) {
			return false, "github lock source input must be canonical"
		}
		if !srcpkg.IsCommitPinnedRef(spec.Ref) {
			return false, "github lock source must be commit-pinned"
		}
	}
	return true, fmt.Sprintf("kind=%s type=%s", trimmedKind, trimmedType)
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

func verifyLockStructure(lock installLock) (bool, string) {
	trimmedName := strings.TrimSpace(lock.Name)
	if trimmedName == "" {
		return false, "lock name is empty"
	}
	if trimmedName != lock.Name {
		return false, "lock name must not contain leading or trailing whitespace"
	}
	if strings.IndexFunc(lock.Name, isC0OrC1ControlRune) >= 0 {
		return false, "lock name must not contain C0/C1 control characters"
	}

	if strings.TrimSpace(lock.InstalledAt) == "" {
		return false, "lock installed_at is empty"
	}
	if _, err := time.Parse(time.RFC3339, lock.InstalledAt); err != nil {
		return false, "lock installed_at must be RFC3339"
	}

	trimmedProfile := strings.TrimSpace(lock.Policy.Profile)
	if trimmedProfile == "" {
		return false, "lock policy profile is empty"
	}
	if strings.IndexFunc(trimmedProfile, isC0OrC1ControlRune) >= 0 {
		return false, "lock policy profile must not contain C0/C1 control characters"
	}
	normalizedProfile := normalizePolicyProfile(trimmedProfile)
	if lock.Policy.Profile != normalizedProfile {
		return false, "lock policy profile must be canonical lowercase without surrounding whitespace"
	}
	if !isSupportedPolicyProfile(normalizedProfile) {
		return false, fmt.Sprintf("lock policy profile is unsupported: %s", lock.Policy.Profile)
	}
	if strings.IndexFunc(lock.Policy.Decision, isC0OrC1ControlRune) >= 0 {
		return false, "lock policy decision must not contain C0/C1 control characters"
	}
	if lock.Policy.Decision != "pass" {
		return false, fmt.Sprintf("lock policy decision must be canonical lowercase pass for installed skill, got %s", lock.Policy.Decision)
	}
	if err := validateSeverityOverrideAudit(lock.Policy.SeverityOverrides); err != nil {
		return false, fmt.Sprintf("lock policy severity_overrides is invalid: %v", err)
	}
	if err := validateLockFindingSummary(lock.Findings); err != nil {
		return false, fmt.Sprintf("lock findings summary is invalid: %v", err)
	}

	if !isCanonicalSHA256Hex(lock.Skill.RootSHA256) {
		return false, "lock skill root_sha256 must be a canonical lowercase 64-char hex digest"
	}
	if len(lock.Skill.Files) == 0 {
		return false, "lock skill files is empty"
	}

	seen := make(map[string]struct{}, len(lock.Skill.Files))
	for _, file := range lock.Skill.Files {
		if strings.TrimSpace(file.Path) == "" {
			return false, "lock file path is empty"
		}
		if !isValidLockRelativePath(file.Path) {
			return false, fmt.Sprintf("lock file path is invalid: %s", file.Path)
		}
		if _, exists := seen[file.Path]; exists {
			return false, fmt.Sprintf("duplicate lock file path: %s", file.Path)
		}
		seen[file.Path] = struct{}{}

		if !isCanonicalSHA256Hex(file.SHA256) {
			return false, fmt.Sprintf("lock file sha256 is invalid: %s", file.Path)
		}
		if file.Bytes < 0 {
			return false, fmt.Sprintf("lock file bytes is negative: %s", file.Path)
		}
	}

	return true, fmt.Sprintf("installed_at=%s files=%d", lock.InstalledAt, len(lock.Skill.Files))
}

func verifyInstallReport(skillPath string, lock installLock) (bool, string) {
	reportPath := filepath.Join(skillPath, installReportFile)
	if err := rejectSymlinkPath(reportPath, "install report file", ruleInstallReportSymlink); err != nil {
		return false, err.Error()
	}
	linkInfo, lstatErr := os.Lstat(reportPath)
	if lstatErr != nil {
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Sprintf("%s: install report file must not be a symlink: %s", ruleInstallReportSymlink, reportPath)
	}
	if !linkInfo.Mode().IsRegular() {
		return false, fmt.Sprintf("%s: install report file must be a regular file: %s", ruleInstallReportSpecialFile, reportPath)
	}

	f, err := os.Open(reportPath)
	if err != nil {
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	defer f.Close()
	if err := ensureInstallReportStableFromOpen(linkInfo, f, reportPath); err != nil {
		return false, err.Error()
	}

	var raw bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&raw, f, maxInstallReportFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return false, fmt.Sprintf("%s: install report exceeds size limit: %s", ruleInstallReportTooLarge, reportPath)
		}
		return false, fmt.Sprintf("failed to read install report: %s", reportPath)
	}
	if !utf8.Valid(raw.Bytes()) {
		return false, fmt.Sprintf("%s: install report must be valid UTF-8: %s", ruleInstallReportInvalidUTF8, reportPath)
	}

	var report installReport
	if err := json.Unmarshal(raw.Bytes(), &report); err != nil {
		return false, "invalid install report JSON"
	}
	if strings.TrimSpace(report.SchemaVersion) == "" {
		return false, "install report schema_version is empty"
	}
	if report.SchemaVersion != reportSchemaVersion {
		return false, fmt.Sprintf("install report schema_version is unsupported: %s", report.SchemaVersion)
	}
	if report.Source.Input != lock.Source.Input || report.Source.Kind != lock.Source.Kind {
		return false, "install report source does not match lock source"
	}
	if strings.TrimSpace(report.PolicyProfile) == "" {
		return false, "install report policy profile is empty"
	}
	if strings.TrimSpace(report.PolicyProfile) != report.PolicyProfile {
		return false, "install report policy profile must not contain leading or trailing whitespace"
	}
	if normalizePolicyProfile(report.PolicyProfile) != report.PolicyProfile {
		return false, "install report policy profile must be canonical lowercase without surrounding whitespace"
	}
	if report.PolicyProfile != lock.Policy.Profile {
		return false, "install report policy profile does not match lock policy"
	}
	if strings.TrimSpace(report.Decision) == "" {
		return false, "install report decision is empty"
	}
	if strings.TrimSpace(report.Decision) != report.Decision {
		return false, "install report decision must not contain leading or trailing whitespace"
	}
	if !strings.EqualFold(report.Decision, lock.Policy.Decision) {
		return false, "install report decision does not match lock policy decision"
	}
	if err := validateSeverityOverrideAudit(report.SeverityOverrides); err != nil {
		return false, fmt.Sprintf("install report severity_overrides is invalid: %v", err)
	}
	if !severityOverridesEqual(report.SeverityOverrides, lock.Policy.SeverityOverrides) {
		return false, "install report severity_overrides does not match lock policy severity_overrides"
	}
	if !strings.EqualFold(report.Decision, "pass") {
		return false, "install report decision must be pass for installed skill"
	}
	if !report.Installed {
		return false, "install report installed must be true"
	}
	if filepath.Clean(report.InstalledPath) != filepath.Clean(skillPath) {
		return false, fmt.Sprintf("install report path mismatch: expected %s, got %s", skillPath, report.InstalledPath)
	}

	reportSummary := summarizeFindingSeverities(report.Findings)
	if reportSummary != lock.Findings {
		return false, "install report findings summary does not match lock findings"
	}

	return true, fmt.Sprintf("schema=%s decision=%s", report.SchemaVersion, report.Decision)
}

func ensureLockfileStableFile(previous os.FileInfo, current os.FileInfo, lockPath string) error {
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: %w (file changed during read): %s", ruleLockfileSourceChanged, errLockfileReadFailed, lockPath)
}

func ensureLockfileStableFromOpen(previous os.FileInfo, opened fileInfoStatter, lockPath string) error {
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("%w: %s", errLockfileReadFailed, lockPath)
	}
	return ensureLockfileStableFile(previous, current, lockPath)
}

func ensureInstallReportStableFile(previous os.FileInfo, current os.FileInfo, reportPath string) error {
	if os.SameFile(previous, current) {
		return nil
	}
	return fmt.Errorf("%s: install report file changed during read: %s", ruleInstallReportSourceChanged, reportPath)
}

func ensureInstallReportStableFromOpen(previous os.FileInfo, opened fileInfoStatter, reportPath string) error {
	current, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("failed to read install report: %s", reportPath)
	}
	return ensureInstallReportStableFile(previous, current, reportPath)
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
	if !utf8.ValidString(in) {
		return false
	}
	if strings.IndexFunc(in, isC0OrC1ControlRune) >= 0 {
		return false
	}
	if strings.TrimSpace(in) == "" {
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
	if hasWindowsDrivePathPrefix(cleaned) {
		return false
	}
	return cleaned == in
}

func hasWindowsDrivePathPrefix(path string) bool {
	if len(path) < 2 {
		return false
	}
	drive := path[0]
	if (drive < 'a' || drive > 'z') && (drive < 'A' || drive > 'Z') {
		return false
	}
	if path[1] != ':' {
		return false
	}
	// Treat both "C:foo" (drive-relative) and "C:/foo" (absolute) as invalid
	// lock-relative paths for cross-platform safety.
	return true
}

func isC0OrC1ControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1f) || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

func validateSeverityOverrideAudit(overrides []severityOverrideAudit) error {
	for idx, override := range overrides {
		ruleID := strings.TrimSpace(override.RuleID)
		if ruleID == "" {
			return fmt.Errorf("entry %d: rule_id is empty", idx)
		}
		if ruleID != override.RuleID {
			return fmt.Errorf("entry %d: rule_id must not contain leading or trailing whitespace", idx)
		}
		if !severityOverrideRuleIDPattern.MatchString(ruleID) {
			return fmt.Errorf("entry %d: rule_id must be canonical uppercase snake case", idx)
		}
		previousSeverity := strings.TrimSpace(override.PreviousSeverity)
		if previousSeverity == "" {
			return fmt.Errorf("entry %d: previous_severity is empty", idx)
		}
		if previousSeverity != override.PreviousSeverity {
			return fmt.Errorf("entry %d: previous_severity must not contain leading or trailing whitespace", idx)
		}
		if !isCanonicalSeverity(previousSeverity) {
			return fmt.Errorf("entry %d: previous_severity must be canonical severity (critical|high|medium|low)", idx)
		}
		effectiveSeverity := strings.TrimSpace(override.EffectiveSeverity)
		if effectiveSeverity == "" {
			return fmt.Errorf("entry %d: effective_severity is empty", idx)
		}
		if effectiveSeverity != override.EffectiveSeverity {
			return fmt.Errorf("entry %d: effective_severity must not contain leading or trailing whitespace", idx)
		}
		if !isCanonicalSeverity(effectiveSeverity) {
			return fmt.Errorf("entry %d: effective_severity must be canonical severity (critical|high|medium|low)", idx)
		}
		if strings.TrimSpace(override.Justification) == "" {
			return fmt.Errorf("entry %d: justification is empty", idx)
		}
		if strings.TrimSpace(override.ApprovedBy) == "" {
			return fmt.Errorf("entry %d: approved_by is empty", idx)
		}
		source := strings.TrimSpace(override.Source)
		if source == "" {
			return fmt.Errorf("entry %d: source is empty", idx)
		}
		if source != override.Source {
			return fmt.Errorf("entry %d: source must not contain leading or trailing whitespace", idx)
		}
		if source != strings.ToLower(source) {
			return fmt.Errorf("entry %d: source must be canonical lowercase", idx)
		}
		if !isAllowedSeverityOverrideSource(source) {
			return fmt.Errorf("entry %d: source must be an allowed origin (cli-override|policy-file)", idx)
		}
		if strings.TrimSpace(override.AppliedAt) == "" {
			return fmt.Errorf("entry %d: applied_at is empty", idx)
		}
		if strings.TrimSpace(override.AppliedAt) != override.AppliedAt {
			return fmt.Errorf("entry %d: applied_at must not contain leading or trailing whitespace", idx)
		}
		if _, err := time.Parse(time.RFC3339, override.AppliedAt); err != nil {
			return fmt.Errorf("entry %d: applied_at must be RFC3339", idx)
		}
	}
	return nil
}

func isCanonicalSeverity(in string) bool {
	switch in {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func isAllowedSeverityOverrideSource(in string) bool {
	switch in {
	case "cli-override", "policy-file":
		return true
	default:
		return false
	}
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

func severityOverridesEqual(a []severityOverrideAudit, b []severityOverrideAudit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
