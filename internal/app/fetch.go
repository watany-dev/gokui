package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watany-dev/gokui/internal/cli/exitcode"
	reportpkg "github.com/watany-dev/gokui/internal/report"
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

const ruleFetchOutputSymlink = "FETCH_OUTPUT_SYMLINK_DETECTED"
const ruleFetchOutputEntrySymlink = "FETCH_OUTPUT_ENTRY_SYMLINK_DETECTED"

var (
	fetchSkillAtomicFunc = fetchSkillAtomic
	writeSourceMetaFunc  = writeSourceMetadata
)

func runFetch(args []string, stdout io.Writer, stderr io.Writer) int {
	requestedJSON := fetchArgsRequestJSON(args)
	requestedSARIF := fetchArgsRequestSARIF(args)

	parsed, err := parseFetchArgs(args)
	if err != nil {
		sourceArg := extractFetchSourceArg(args)
		report := fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			Status:        "ERROR",
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
			Status:        "ERROR",
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
			Status:        "ERROR",
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

	skillRoot, cleanup, err := fetchGitHubSkill(spec)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			Status:        "ERROR",
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
	if err := rejectSymlinkPath(outRoot, "fetch output root", ruleFetchOutputSymlink); err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			Status:        "ERROR",
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

	dest, err := fetchSkillAtomicFunc(skillRoot, outRoot, meta.Name)
	if err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
			Status:        "ERROR",
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
	if err := writeSourceMetaFunc(dest, sourceMetadata{
		Schema:          sourceMetadataSchemaVersion,
		SourceInput:     parsed.Source,
		SourceKind:      "github-source",
		ResolvedRef:     spec.Ref,
		FetchedAt:       time.Now().UTC().Format(time.RFC3339),
		SkillRootSHA256: rootHash,
	}); err != nil {
		if emitFetchStructuredError(parsed.Format, stdout, stderr, fetchErrorReport{
			SchemaVersion: reportSchemaVersion,
			Status:        "ERROR",
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
		Decision: "FETCHED",
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

func fetchArgsRequestJSON(args []string) bool {
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

func fetchArgsRequestSARIF(args []string) bool {
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

func extractFetchSourceArg(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--out" || arg == "--format" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--out=") || strings.HasPrefix(arg, "--format=") {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func writeFetchJSONError(stdout io.Writer, stderr io.Writer, report fetchErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, fetchErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render fetch error report")
		return exitcode.Error.Int()
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return exitcode.Error.Int()
}

func writeFetchSARIFError(stdout io.Writer, stderr io.Writer, report fetchErrorReport) int {
	report.Status = "ERROR"
	report.ErrorCode = normalizeJSONErrorCode(report.ErrorCode, fetchErrorCodeUnknown)
	if report.RuleID == "" {
		report.RuleID = inferRuleIDForJSONError(report.Message)
	}
	out, err := json.MarshalIndent(buildFetchSARIFErrorReport(report), "", "  ")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "failed to render fetch SARIF error report")
		return exitcode.Error.Int()
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", out)
	return exitcode.Error.Int()
}

func emitFetchStructuredError(format string, stdout io.Writer, stderr io.Writer, report fetchErrorReport) bool {
	switch format {
	case "json":
		_ = writeFetchJSONError(stdout, stderr, report)
		return true
	case "sarif":
		_ = writeFetchSARIFError(stdout, stderr, report)
		return true
	default:
		return false
	}
}

func parseFetchArgs(args []string) (fetchArgs, error) {
	out := fetchArgs{Format: "human"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--out":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --out")
			}
			out.Out = args[i+1]
			i++
		case strings.HasPrefix(arg, "--out="):
			out.Out = strings.TrimPrefix(arg, "--out=")
		case arg == "--format":
			if i+1 >= len(args) {
				return fetchArgs{}, fmt.Errorf("missing value for --format")
			}
			out.Format = args[i+1]
			i++
		case strings.HasPrefix(arg, "--format="):
			out.Format = strings.TrimPrefix(arg, "--format=")
		case strings.HasPrefix(arg, "-"):
			return fetchArgs{}, fmt.Errorf("unknown fetch option: %s", arg)
		default:
			if out.Source != "" {
				return fetchArgs{}, fmt.Errorf("fetch accepts exactly one source")
			}
			out.Source = arg
		}
	}

	if out.Source == "" {
		return fetchArgs{}, fmt.Errorf("fetch source is required")
	}
	if strings.TrimSpace(out.Out) == "" {
		return fetchArgs{}, fmt.Errorf("fetch output root is required (--out)")
	}
	if out.Format != "human" && out.Format != "json" && out.Format != "sarif" && out.Format != "compact" {
		return fetchArgs{}, fmt.Errorf("unsupported fetch format: %s", out.Format)
	}
	return out, nil
}

func buildFetchSARIFReport(report fetchReport) inspectSARIFReport {
	inspectEquivalent := inspectReport{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		Source:        report.Source,
		Decision:      report.Decision,
		Findings:      []inspectFinding{},
		Note:          fmt.Sprintf("fetch output=%s; %s", report.Output, report.Note),
	}
	return buildInspectSARIFReport(inspectEquivalent)
}

func buildFetchSARIFErrorReport(report fetchErrorReport) inspectSARIFReport {
	ruleID := report.ErrorCode
	if report.RuleID != "" {
		ruleID = report.RuleID
	}
	return reportpkg.SARIFErrorDocument(ruleID, report.ErrorCode, report.Message, inspectSARIFProperties{
		SchemaVersion: report.SchemaVersion,
		PreRelease:    true,
		SourceInput:   report.Source.Input,
		SourceKind:    report.Source.Kind,
		Decision:      report.Status,
		Note:          fmt.Sprintf("%s; error_code=%s output=%s", report.Note, report.ErrorCode, report.Output),
	})
}

func buildFetchCompactSummary(report fetchReport) string {
	return fmt.Sprintf(
		"fetch decision=%s source_kind=%s source=%q output=%q",
		report.Decision,
		report.Source.Kind,
		report.Source.Input,
		report.Output,
	)
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
	if err := rejectSymlinkPath(finalPath, "fetch output entry", ruleFetchOutputEntrySymlink); err != nil {
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
