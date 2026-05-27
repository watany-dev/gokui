package scan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	"github.com/watany-dev/gokui/internal/rule"
)

const maxScanFileBytes = 500_000
const maxShebangProbeBytes = 256
const maxDecodedArtifactBytes = 1_000_000
const maxDecodedRecursionDepth = 3
const maxDecodedCandidatesPerLine = 16
const maxJoinedContinuationLines = 4
const minBase64CandidateLength = 40
const minHexCandidateLength = 64

var scanMaxFiles = 10_000

const (
	ruleScanSymlinkInSource = "SYMLINK_IN_SCAN_SOURCE"
	ruleScanFileCount       = "SCAN_FILE_COUNT_EXCEEDED"
	ruleScanSpecialFile     = "SPECIAL_FILE_IN_SCAN_SOURCE"
	ruleScanSourceChanged   = "SCAN_SOURCE_CHANGED_DURING_READ"
)

// Finding represents one scan result.
type Finding struct {
	ID       string
	Severity string
	File     string
	Line     int
	Summary  string
}

// ScanSkillRoot scans markdown instruction files under skillRoot.
func ScanSkillRoot(skillRoot string) ([]Finding, error) {
	targets, err := scanTargets(skillRoot)
	if err != nil {
		return nil, err
	}

	findings := make([]Finding, 0)
	for _, target := range targets {
		findings = append(findings, classifyPathRisks(target.Relative)...)
		if target.Kind == "unknown" {
			findings = append(findings, newFinding(rule.UnknownFileType, target.Relative, 1, "unclassified file type requires manual review"))
			continue
		}
		fileFindings, err := scanTextFile(target)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fileFindings...)
	}
	findings = deduplicateFindings(findings)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity < findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})

	return findings, nil
}

func scanTextFile(target scanTarget) ([]Finding, error) {
	in, err := os.Open(target.Absolute)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan file %s: %w", target.Relative, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to read scan file %s: %w", target.Relative, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: scan source contains non-regular file: %s", ruleScanSpecialFile, target.Relative)
	}
	if target.Info != nil && !os.SameFile(target.Info, info) {
		return nil, fmt.Errorf("%s: scan source changed during read: %s", ruleScanSourceChanged, target.Relative)
	}

	var contentBuf bytes.Buffer
	if _, err := limitio.CopyWithStrictLimit(&contentBuf, in, maxScanFileBytes); err != nil {
		if errors.Is(err, limitio.ErrSizeExceeded) {
			return []Finding{newFinding(rule.LargeTextFile, target.Relative, 1, "text file exceeds scan size limit")}, nil
		}
		return nil, fmt.Errorf("failed to read scan file %s: %w", target.Relative, err)
	}
	content := contentBuf.Bytes()
	if target.Kind != "unknown" && !utf8.Valid(content) {
		return []Finding{newFinding(rule.NonUTF8Text, target.Relative, 1, "text scan input must be valid UTF-8")}, nil
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	referenceHosts := map[string]string{}
	if target.Kind == "markdown" {
		referenceHosts = buildMarkdownReferenceHostIndex(lines)
	}
	findings := make([]Finding, 0)
	for i, line := range lines {
		lineNum := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}

		normalized, changed := normalizeLineNFKC(line)
		if changed {
			findings = append(findings, newFinding(rule.NFKCChangesText, target.Relative, lineNum, "Unicode compatibility normalization changes text"))
		}
		for _, variant := range scanLineVariants(lines, i, line, normalized, changed) {
			findings = append(findings, scanVariantThreatFindings(variant, target, lineNum)...)
			if target.Kind == "markdown" {
				findings = append(findings, classifyMarkdownReferenceLinkSpoofing(variant, target.Relative, lineNum, referenceHosts)...)
				if joined, ok := buildMarkdownReferenceUsageContinuationVariant(lines, i); ok {
					findings = append(findings, classifyMarkdownReferenceLinkSpoofing(joined, target.Relative, lineNum, referenceHosts)...)
				}
			}
			findings = append(findings, scanDecodedVariantThreatFindings(variant, target, lineNum, 0)...)
		}
		findings = append(findings, classifyUnicodeThreats(line, target.Relative, lineNum)...)
	}

	return deduplicateFindings(findings), nil
}

func scanVariantThreatFindings(variant string, target scanTarget, lineNum int) []Finding {
	findings := make([]Finding, 0, 8)
	normalizedAssignDefaults := normalizeShellAssignDefaultExpansions(variant)
	normalizedAssignDefaults = normalizeShellSpecialProcParams(normalizedAssignDefaults)
	curlSourceStdinMatch := curlPipeSourceStdInExecPattern.MatchString(variant)
	if !curlSourceStdinMatch && normalizedAssignDefaults != variant {
		curlSourceStdinMatch = curlPipeSourceStdInExecPattern.MatchString(normalizedAssignDefaults)
	}
	if curlPipePattern.MatchString(variant) || curlSourceStdinMatch || curlSubshellExecPattern.MatchString(variant) || curlBacktickExecPattern.MatchString(variant) || curlDotSubshellExecPattern.MatchString(variant) || curlDotBacktickExecPattern.MatchString(variant) || powerShellRemoteEvalPattern.MatchString(variant) || powerShellFetchEvalPattern.MatchString(variant) || pythonRemoteExecPattern.MatchString(variant) || nodeRemoteEvalPattern.MatchString(variant) || nodeRemoteFunctionExecPattern.MatchString(variant) || rubyRemoteEvalPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "CURL_PIPE_SHELL",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "network output reaches shell/interpreter execution",
		})
	}
	base64SourceStdinMatch := base64PipeSourceStdInExec.MatchString(variant)
	if !base64SourceStdinMatch && normalizedAssignDefaults != variant {
		base64SourceStdinMatch = base64PipeSourceStdInExec.MatchString(normalizedAssignDefaults)
	}
	if base64PipeExec.MatchString(variant) || base64SourceStdinMatch || base64SubshellExec.MatchString(variant) || base64DotSubshellExec.MatchString(variant) || powerShellFromBase64ExecPattern.MatchString(variant) || pythonBase64ExecPattern.MatchString(variant) || nodeBase64EvalPattern.MatchString(variant) || perlBase64EvalPattern.MatchString(variant) || rubyBase64EvalPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "BASE64_PIPE_EXEC",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "decoded payload reaches interpreter execution",
		})
	}
	hexSourceStdinMatch := hexPipeSourceStdInExec.MatchString(variant)
	if !hexSourceStdinMatch && normalizedAssignDefaults != variant {
		hexSourceStdinMatch = hexPipeSourceStdInExec.MatchString(normalizedAssignDefaults)
	}
	if hexPipeExec.MatchString(variant) || hexSourceStdinMatch || hexSubshellExec.MatchString(variant) || hexDotSubshellExec.MatchString(variant) || powerShellFromHexExecPattern.MatchString(variant) || pythonHexExecPattern.MatchString(variant) || nodeHexEvalPattern.MatchString(variant) || perlHexEvalPattern.MatchString(variant) || rubyHexEvalPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "HEX_PIPE_EXEC",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "hex-decoded payload reaches interpreter execution",
		})
	}
	if encodedCmdExec.MatchString(variant) || encodedCmdExecVariableArg.MatchString(variant) || hasEncodedCommandExecLine(variant) {
		findings = append(findings, Finding{
			ID:       "ENCODED_COMMAND_EXEC",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "encoded command execution flag detected",
		})
	}
	if hasChmodExecChain(variant) {
		findings = append(findings, Finding{
			ID:       "CHMOD_EXEC_CHAIN",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "chmod +x followed by execution of the same local artifact",
		})
	}
	if hasHomeConfigWrite(variant) {
		findings = append(findings, Finding{
			ID:       "WRITES_HOME_CONFIG",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "writes to shell/ssh/cron/launch-agent configuration path",
		})
	}
	if hasSecretExfilLine(variant) {
		findings = append(findings, Finding{
			ID:       "SECRET_EXFIL",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "secret path access combined with network exfiltration command",
		})
	}
	if hasBashWildcardPermission(variant) {
		findings = append(findings, Finding{
			ID:       "ALLOWED_TOOLS_BASH_WILDCARD",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "broad Bash wildcard permission detected",
		})
	}
	if isUnpinnedRuntimeToolLine(variant) {
		findings = append(findings, Finding{
			ID:       "UNPINNED_RUNTIME_TOOL",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "unpinned runtime tool execution detected",
		})
	}
	findings = append(findings, classifyURLRisks(variant, target.Relative, lineNum, target.Kind == "markdown")...)

	if target.Kind != "markdown" {
		return findings
	}
	if fakePrereqPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "FAKE_PREREQ_EXECUTION",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "prerequisite text asks to download and run code",
		})
	}
	if externalBinaryPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "EXTERNAL_BINARY_DOWNLOAD",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "external binary archive download instruction detected",
		})
	}
	if promptOverridePattern.MatchString(variant) || hasPromptOverrideApproximatePhrase(variant) {
		findings = append(findings, Finding{
			ID:       "PROMPT_OVERRIDE_LANGUAGE",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "prompt override language detected",
		})
	}
	if passwordArchivePattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "PASSWORD_PROTECTED_ARCHIVE",
			Severity: "high",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "password-protected archive instruction detected",
		})
	}
	if rawHTMLPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "RAW_HTML_MARKUP",
			Severity: "medium",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "raw HTML markup detected in markdown content",
		})
	}
	findings = append(findings, classifyMarkdownLinkSpoofing(variant, target.Relative, lineNum)...)
	return findings
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
