package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	reportpkg "github.com/watany-dev/gokui/internal/report"
	rulepkg "github.com/watany-dev/gokui/internal/rule"
	skillpkg "github.com/watany-dev/gokui/internal/skill"
	srcpkg "github.com/watany-dev/gokui/internal/source"
)

type fetchArgs struct {
	Source string
	Out    string
	Format string
}

type fetchReport struct {
	SchemaVersion string `json:"schema_version"`
	Source        source `json:"source"`
	Output        string `json:"output"`
	Decision      string `json:"decision"`
	Note          string `json:"note"`
}

type fetchErrorReport struct {
	SchemaVersion string `json:"schema_version"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code"`
	RuleID        string `json:"rule_id,omitempty"`
	Message       string `json:"message"`
	Source        source `json:"source"`
	Output        string `json:"output"`
	Note          string `json:"note"`
}

const (
	fetchErrorCodeArgsInvalid          = "FETCH_ARGS_INVALID"
	fetchErrorCodeSourceUnsupported    = "FETCH_SOURCE_UNSUPPORTED"
	fetchErrorCodeSourceInvalid        = "FETCH_SOURCE_INVALID"
	fetchErrorCodeSourceRefNotPinned   = "FETCH_SOURCE_REF_NOT_PINNED"
	fetchErrorCodeSourceDownloadFailed = "FETCH_SOURCE_DOWNLOAD_FAILED"
	fetchErrorCodeSkillInvalid         = "FETCH_SKILL_INVALID"
	fetchErrorCodeOutputPrepareFailed  = "FETCH_OUTPUT_PREPARE_FAILED"
	fetchErrorCodeCopyFailed           = "FETCH_COPY_FAILED"
	fetchErrorCodeDigestFailed         = "FETCH_DIGEST_FAILED"
	fetchErrorCodeMetadataWriteFailed  = "FETCH_SOURCE_METADATA_WRITE_FAILED"
	fetchErrorCodeUnknown              = "FETCH_FAILED"
)

type fetchDeps struct {
	FetchGitHubSkill    func(srcpkg.GitHubSpec) (string, func(), error)
	FetchSkillAtomic    func(skillRoot string, outRoot string, skillName string) (string, error)
	WriteSourceMetadata func(skillRoot string, meta sourceMetadata) error
	Now                 func() time.Time
}

func defaultFetchDeps() fetchDeps {
	return fetchDeps{
		FetchGitHubSkill:    srcpkg.FetchGitHubSkill,
		FetchSkillAtomic:    fetchSkillAtomic,
		WriteSourceMetadata: writeSourceMetadata,
		Now:                 time.Now,
	}
}

func runFetch(args []string, stdout io.Writer, stderr io.Writer) int {
	return runFetchWithDeps(args, stdout, stderr, defaultFetchDeps())
}

func runFetchWithDeps(args []string, stdout io.Writer, stderr io.Writer, deps fetchDeps) int {
	requestedJSON := argsRequestFormat(args, "json")
	requestedSARIF := argsRequestFormat(args, "sarif")
	deps = normalizeFetchDeps(deps)

	parsed, err := parseFetchArgs(args)
	if err != nil {
		sourceArg := extractFetchSourceArg(args)
		report := fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeArgsInvalid,
			Message:       err.Error(),
			Source: source{
				Input: sourceArg,
				Kind:  detectSourceKind(sourceArg),
			},
			Output: "",
			Note:   "fetch failed before source evaluation",
		}
		if requestedJSON {
			return writeFetchJSONError(stdout, stderr, report)
		}
		if requestedSARIF {
			return writeFetchSARIFError(stdout, stderr, report)
		}
		_, _ = fmt.Fprintf(stderr, "%s\n\n%s\n", err.Error(), usage())
		return exitcode.Error.Int()
	}

	sourceKind := detectSourceKind(parsed.Source)
	if sourceKind != "github-source" {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeSourceUnsupported,
			Message:       "fetch currently supports github sources only",
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "fetch supports github-source only in this release",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, "fetch currently supports github sources only")
		return exitcode.Error.Int()
	}

	spec, err := srcpkg.ParseGitHubSource(parsed.Source)
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeSourceInvalid,
			Message:       fmt.Sprintf("invalid github source: %v", err),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "fetch source syntax validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "invalid github source: %v\n", err)
		return exitcode.Error.Int()
	}
	if !srcpkg.IsCommitPinnedRef(spec.Ref) {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeSourceRefNotPinned,
			Message:       "fetch requires a commit-pinned ref (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)",
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "floating refs are not allowed for fetch",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, "fetch requires a commit-pinned ref (e.g. @8f3c2d1a4b5c6d7e8f901234567890abcdef1234)")
		return exitcode.Error.Int()
	}

	skillRoot, cleanup, err := deps.FetchGitHubSkill(spec)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeSourceDownloadFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "failed while downloading or materializing source",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	meta, err := skillpkg.ValidateFrontmatter(filepath.Join(skillRoot, "SKILL.md"), maxSkillFrontmatterBytes)
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeSkillInvalid,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "fetched source failed skill frontmatter validation",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	outRoot := filepath.Clean(parsed.Out)
	if err := rejectSymlinkPath(outRoot, "fetch output root", rulepkg.FetchOutputSymlink.ID); err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeOutputPrepareFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "output root validation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeOutputPrepareFailed,
			Message:       fmt.Sprintf("failed to prepare fetch output root: %v", err),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "output directory creation failed",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintf(stderr, "failed to prepare fetch output root: %v\n", err)
		return exitcode.Error.Int()
	}

	dest, err := deps.FetchSkillAtomic(skillRoot, outRoot, meta.Name)
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeCopyFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: parsed.Out,
			Note:   "failed while staging fetched files to output root",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	_, rootHash, err := buildFileDigestsFiltered(dest, map[string]struct{}{
		sourceMetadataFile: {},
	})
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeDigestFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: dest,
			Note:   "failed while computing fetched source digest",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}
	if err := deps.WriteSourceMetadata(dest, sourceMetadata{
		Schema:          sourceMetadataSchemaVersion,
		SourceInput:     parsed.Source,
		SourceKind:      "github-source",
		ResolvedRef:     spec.Ref,
		FetchedAt:       deps.Now().UTC().Format(time.RFC3339),
		SkillRootSHA256: rootHash,
	}); err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        reportStatusError,
			ErrorCode:     fetchErrorCodeMetadataWriteFailed,
			Message:       err.Error(),
			Source: source{
				Input: parsed.Source,
				Kind:  sourceKind,
			},
			Output: dest,
			Note:   "failed while writing source metadata",
		}) {
			return exitcode.Error.Int()
		}
		_, _ = fmt.Fprintln(stderr, err.Error())
		return exitcode.Error.Int()
	}

	report := fetchReport{
		SchemaVersion: reportSchemaVersion,
		Source: source{
			Input: parsed.Source,
			Kind:  sourceKind,
		},
		Output:   dest,
		Decision: reportDecisionFetchDone,
		Note:     "pre-release fetch materializes commit-pinned github source into quarantine",
	}

	if parsed.Format == "json" {
		out, _ := json.MarshalIndent(report, "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	}
	if parsed.Format == "sarif" {
		out, _ := json.MarshalIndent(buildFetchSARIFReport(report), "", "  ")
		_, _ = fmt.Fprintf(stdout, "%s\n", out)
		return exitcode.OK.Int()
	}
	if parsed.Format == "compact" {
		_, _ = fmt.Fprintf(stdout, "%s\n", buildFetchCompactSummary(report))
		return exitcode.OK.Int()
	}

	_, _ = fmt.Fprintln(stdout, "gokui fetch report (pre-release)")
	_, _ = fmt.Fprintf(stdout, "source: %s (%s)\n", report.Source.Input, report.Source.Kind)
	_, _ = fmt.Fprintf(stdout, "decision: %s\n", report.Decision)
	_, _ = fmt.Fprintf(stdout, "output: %s\n", report.Output)
	return exitcode.OK.Int()
}

func normalizeFetchDeps(deps fetchDeps) fetchDeps {
	if deps.FetchGitHubSkill == nil {
		deps.FetchGitHubSkill = srcpkg.FetchGitHubSkill
	}
	if deps.FetchSkillAtomic == nil {
		deps.FetchSkillAtomic = fetchSkillAtomic
	}
	if deps.WriteSourceMetadata == nil {
		deps.WriteSourceMetadata = writeSourceMetadata
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return deps
}

func writeFetchJSONError(stdout io.Writer, stderr io.Writer, report fetchErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, fetchErrorCodeUnknown)
	return writeIndentedJSONLine(stdout, stderr, report, "failed to render fetch error report")
}

func writeFetchSARIFError(stdout io.Writer, stderr io.Writer, report fetchErrorReport) int {
	report.Status, report.ErrorCode, report.RuleID = normalizeStructuredErrorFields(report.ErrorCode, report.RuleID, report.Message, fetchErrorCodeUnknown)
	return writeIndentedJSONLine(stdout, stderr, buildFetchSARIFErrorReport(report), "failed to render fetch SARIF error report")
}

func emitFetchStructuredError(format string, stdout io.Writer, stderr io.Writer, report fetchErrorReport) bool {
	return emitStructuredError(format,
		func() { _ = writeFetchJSONError(stdout, stderr, report) },
		func() { _ = writeFetchSARIFError(stdout, stderr, report) },
	)
}

func buildFetchSARIFReport(report fetchReport) reportpkg.SARIFDocument {
	return buildFindingsSARIFReport(
		report.SchemaVersion,
		true,
		report.Source,
		report.Decision,
		nil,
		fmt.Sprintf("fetch output=%s; %s", report.Output, report.Note),
	)
}

func buildFetchSARIFErrorReport(report fetchErrorReport) reportpkg.SARIFDocument {
	return reportpkg.SARIFErrorDocument(structuredErrorRuleID(report.ErrorCode, report.RuleID), report.ErrorCode, report.Message, reportpkg.SARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Source.Input,
		SourceKind:    report.Source.Kind,
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s output=%s", report.Note, report.ErrorCode, report.Output),
	})
}

func buildFetchCompactSummary(report fetchReport) string {
	return reportpkg.FetchCompactSummary(report.Decision, report.Source.Kind, report.Source.Input, report.Output)
}

func fetchSkillAtomic(skillRoot string, outRoot string, skillName string) (string, error) {
	if outInfo, err := os.Stat(outRoot); err == nil {
		if !outInfo.IsDir() {
			return "", fmt.Errorf("failed to check fetch output target: %s is not a directory", outRoot)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check fetch output target: %w", err)
	}

	finalPath := filepath.Join(outRoot, skillName)
	if err := rejectSymlinkPath(finalPath, "fetch output entry", rulepkg.FetchOutputEntrySymlink.ID); err != nil {
		return "", err
	}
	if _, err := os.Stat(finalPath); err == nil {
		return "", fmt.Errorf("fetch output already contains skill: %s", finalPath)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check fetch output target: %w", err)
	}

	stagingRoot, err := os.MkdirTemp(outRoot, ".gokui-fetch-*")
	if err != nil {
		return "", fmt.Errorf("failed to create fetch staging directory: %w", err)
	}
	defer os.RemoveAll(stagingRoot)

	stagedSkill := filepath.Join(stagingRoot, skillName)
	if err := copyTreeNormalized(skillRoot, stagedSkill); err != nil {
		return "", err
	}
	if err := os.Rename(stagedSkill, finalPath); err != nil {
		return "", fmt.Errorf("failed to finalize fetch: %w", err)
	}
	return finalPath, nil
}
