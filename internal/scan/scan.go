package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/watany-dev/gokui/internal/limitio"
	"golang.org/x/text/unicode/norm"
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

var (
	curlPipePattern                 = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python3?|node|ruby|perl)\b`)
	curlSubshellExecPattern         = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,200}\$\(\s*(?:curl|wget)\b`)
	curlBacktickExecPattern         = regexp.MustCompile("(?i)\\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\\b[^\\n]{0,200}`\\s*(?:curl|wget)\\b")
	curlDotSubshellExecPattern      = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\(\s*(?:curl|wget)\b`)
	curlDotBacktickExecPattern      = regexp.MustCompile("(?i)(?:^|[;&|]\\s*)\\.\\s+`\\s*(?:curl|wget)\\b")
	powerShellRemoteEvalPattern     = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\n]{0,260}(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,220}https?://|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://)`)
	powerShellFetchEvalPattern      = regexp.MustCompile(`(?i)(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl(?:\.exe)?|wget(?:\.exe)?)\b[^\n]{0,260}https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b|\bdownload(?:string|data)\b\s*\(\s*['"]?https?://[^\n]{0,260}\b(?:iex|invoke-expression)\b)`)
	pythonRemoteExecPattern         = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:requests\.get\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.text|urllib\.request\.urlopen\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read\s*\(\s*\))`)
	pythonBase64ExecPattern         = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:__import__\(\s*['"]base64['"]\s*\)\.b64decode|base64\.b64decode|b64decode)\s*\(`)
	pythonHexExecPattern            = regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:bytes\.fromhex|bytearray\.fromhex|binascii\.unhexlify)\s*\(`)
	nodeRemoteEvalPattern           = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:(?:await\s+)?fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)|(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))`)
	nodeRemoteFunctionExecPattern   = regexp.MustCompile(`(?i)\bnew\s+function\s*\(\s*(?:(?:await\s+)?\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\)|\(\s*await\s+fetch\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)\.text\s*\(\s*\))\s*\)\s*\(`)
	nodeBase64EvalPattern           = regexp.MustCompile(`(?i)\b(?:eval|new\s+function)\s*\(\s*(?:atob\s*\(|buffer\s*\.\s*from\s*\([^)\n]{0,260}['"]base64['"]\s*\)\s*\.toString\s*\()`)
	nodeHexEvalPattern              = regexp.MustCompile(`(?i)\b(?:eval|new\s+function)\s*\(\s*buffer\s*\.\s*from\s*\([^)\n]{0,260}['"]hex['"]\s*\)\s*\.toString\s*\(`)
	perlBase64EvalPattern           = regexp.MustCompile(`(?i)\beval\b[^\n]{0,260}\b(?:decode_base64|mime::base64::decode_base64)\s*\(`)
	perlHexEvalPattern              = regexp.MustCompile(`(?i)\beval\b[^\n]{0,260}\bpack\s*\(\s*['"]h\*['"]\s*,`)
	rubyBase64EvalPattern           = regexp.MustCompile(`(?i)\beval\s*\([^)\n]{0,260}(?:base64\.decode64|strict_decode64|urlsafe_decode64)\s*\(`)
	rubyHexEvalPattern              = regexp.MustCompile(`(?i)\beval\s*\([^)\n]{0,260}\.pack\s*\(\s*['"]h\*['"]`)
	rubyRemoteEvalPattern           = regexp.MustCompile(`(?i)\beval\s*\(\s*(?:net::http\.get\s*\(\s*uri\s*\(\s*['"]https?://[^'"]+['"]\s*\)\s*\)|uri\.open\s*\(\s*['"]https?://[^'"]+['"]\s*\)\.read)`)
	base64PipeExec                  = regexp.MustCompile(`(?i)\b(?:base64|openssl\s+base64)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	base64SubshellExec              = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,220}\$\([^)\n]{0,260}\b(?:base64|openssl\s+base64)\b[^)\n]{0,200}\s(?:-d|--decode)\b[^)\n]{0,120}\)`)
	base64DotSubshellExec           = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\([^)\n]{0,260}\b(?:base64|openssl\s+base64)\b[^)\n]{0,200}\s(?:-d|--decode)\b[^)\n]{0,120}\)`)
	powerShellFromBase64ExecPattern = regexp.MustCompile(`(?i)(?:\b(?:iex|invoke-expression)\b[^\n]{0,320}\bfrombase64string\s*\(|\bfrombase64string\s*\([^\n]{0,320}\b(?:iex|invoke-expression)\b)`)
	hexPipeExec                     = regexp.MustCompile(`(?i)\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^\n|]{0,300}\|\s*(?:sh|bash|zsh|pwsh|powershell|python|node)\b`)
	hexSubshellExec                 = regexp.MustCompile(`(?i)\b(?:sh|bash|zsh|source|pwsh|powershell|eval|python3?|node|ruby|perl)\b[^\n]{0,220}\$\([^)\n]{0,260}\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^)\n]{0,200}\)`)
	hexDotSubshellExec              = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s+\$\([^)\n]{0,260}\b(?:xxd\s+-r(?:\s+-p)?|unhexlify|fromhex|hexdecode)\b[^)\n]{0,200}\)`)
	powerShellFromHexExecPattern    = regexp.MustCompile(`(?i)(?:\b(?:iex|invoke-expression)\b[^\n]{0,320}\bfromhexstring\s*\(|\bfromhexstring\s*\([^\n]{0,320}\b(?:iex|invoke-expression)\b)`)
	encodedCmdExec                  = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,240}\s-(?:encodedcommand|enc)\s+[a-z0-9+/=]{12,}\b`)
	encodedCmdExecVariableArg       = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,240}\s-(?:encodedcommand|enc)\s+(?:\$[a-z0-9_:{\}\.\(\)\-]+|%[a-z0-9_]+%)`)

	promptOverridePattern = regexp.MustCompile(`(?i)\b(?:ignore|override|bypass)\b.{0,80}\b(?:previous|prior|system|higher|earlier)\b.{0,40}\b(?:instruction|instructions|prompt|prompts)\b`)

	externalBinaryPattern     = regexp.MustCompile(`(?i)\bhttps?://\S+\.(?:zip|exe|msi|dmg|pkg|tar\.gz|tgz)\b`)
	urlPattern                = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"')\]]+`)
	rawHTMLPattern            = regexp.MustCompile(`(?i)<\s*(?:script|iframe|object|embed|form|link|meta|img|svg|video|audio)\b`)
	markdownLinkPattern       = regexp.MustCompile(`\[(?P<label>[^\]]+)\]\((?P<target>https?://[^)\s]+)\)`)
	passwordArchivePattern    = regexp.MustCompile(`(?i)(?:\b(?:password|passphrase|passwd|encrypted)\b.{0,80}\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b|\b(?:zip|7z|rar|archive|tar|tgz|tar\.gz)\b.{0,80}\b(?:password|passphrase|passwd|encrypted)\b)`)
	goSemverExactPattern      = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$`)
	goPseudoVersionPattern    = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-[0-9a-f]{12}$`)
	hexCommitRefPattern       = regexp.MustCompile(`^[0-9a-f]{12,40}$`)
	remoteScriptImportPattern = regexp.MustCompile(`(?i)\b(?:source|bash|sh|zsh)\b\s*<\(\s*(?:curl|wget)\b`)
	remoteScriptDotImport     = regexp.MustCompile(`(?i)(?:^|[;&|]\s*)\.\s*<\(\s*(?:curl|wget)\b`)
	remoteDenoRunPattern      = regexp.MustCompile(`(?i)\bdeno\b\s+run\b[^\n]{0,300}\bhttps?://`)

	fakePrereqPattern = regexp.MustCompile(`(?i)\b(?:required|required prerequisite|you must|before use)\b.{0,120}\b(?:download|install)\b.{0,200}\b(?:run|execute|bash|sh|powershell|chmod \+x)\b`)
)

var promptOverridePhrases = [][]string{
	{"ignore", "previous", "instructions"},
	{"ignore", "all", "previous", "instructions"},
	{"disregard", "previous", "instructions"},
	{"override", "system", "prompt"},
	{"bypass", "safety", "instructions"},
}

type scanTarget struct {
	Absolute string
	Relative string
	Kind     string
	Info     os.FileInfo
}

type encodedCandidate struct {
	kind  string
	value string
}

var scriptLikeExtensions = map[string]struct{}{
	".sh":   {},
	".bash": {},
	".zsh":  {},
	".ps1":  {},
	".bat":  {},
	".cmd":  {},
	".py":   {},
	".js":   {},
	".jsx":  {},
	".ts":   {},
	".tsx":  {},
	".mjs":  {},
	".cjs":  {},
	".psm1": {},
	".psd1": {},
	".rb":   {},
	".pl":   {},
	".pm":   {},
	".go":   {},
}

var manifestLikeFiles = map[string]struct{}{
	"package.json":     {},
	"pyproject.toml":   {},
	"requirements.txt": {},
	"uv.lock":          {},
	"go.mod":           {},
	"gemfile":          {},
	"deno.json":        {},
}

var urlShortenerHosts = map[string]struct{}{
	"bit.ly":      {},
	"tinyurl.com": {},
	"t.co":        {},
	"goo.gl":      {},
	"ow.ly":       {},
	"is.gd":       {},
	"buff.ly":     {},
	"cutt.ly":     {},
	"rb.gy":       {},
	"shorturl.at": {},
}

var pasteSiteHosts = map[string]struct{}{
	"pastebin.com":               {},
	"hastebin.com":               {},
	"ghostbin.com":               {},
	"dpaste.com":                 {},
	"gist.github.com":            {},
	"gist.githubusercontent.com": {},
}

var homeConfigPathHints = []string{
	"~/.bashrc",
	"~/.zshrc",
	"~/.profile",
	"~/.bash_profile",
	"~/.config/fish/config.fish",
	"~/.ssh/config",
	"~/.ssh/authorized_keys",
	"~/library/launchagents/",
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/var/spool/cron/",
}

var secretPathHints = []string{
	".env",
	"~/.ssh/",
	"/.ssh/",
	"~/.aws/",
	"/.aws/",
	"id_rsa",
	"id_ed25519",
	"credentials",
	"api_key",
	"token",
	"cookies",
	"keychain",
	"wallet",
}

var secretExfilNetworkCommand = regexp.MustCompile(`(?i)\b(?:curl|wget|invoke-webrequest|invoke-restmethod|requests\.post|netcat|nc)\b`)
var bashWildcardPermissionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\ballowed(?:[_ -]?tools?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\b.*(?:\*|\ball\b).*allowed(?:[_ -]?tools?)\b`),
	regexp.MustCompile(`(?i)\btool(?:[_ -]?permissions?)\b.*\bbash\b.*(?:\*|\ball\b)`),
	regexp.MustCompile(`(?i)\bbash\s*\(\s*\*\s*\)`),
}

// confusableFilenameRunes maps a conservative subset of Cyrillic/Greek homoglyphs
// that are commonly used to visually mimic ASCII letters in filenames.
var confusableFilenameRunes = map[rune]rune{
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y',
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'α': 'a', 'β': 'b', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x',
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
			findings = append(findings, Finding{
				ID:       "UNKNOWN_FILE_TYPE",
				Severity: "medium",
				File:     target.Relative,
				Line:     1,
				Summary:  "unclassified file type requires manual review",
			})
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

func classifyPathRisks(relPath string) []Finding {
	name := filepath.Base(relPath)
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if stem == "" {
		stem = name
	}
	findings := make([]Finding, 0, 2)
	if hasMixedScriptLetters(stem) {
		findings = append(findings, Finding{
			ID:       "MIXED_SCRIPT_FILENAME",
			Severity: "medium",
			File:     filepath.ToSlash(relPath),
			Line:     1,
			Summary:  "filename contains mixed writing scripts",
		})
	}
	if hasASCIIConfusableFilename(stem) {
		findings = append(findings, Finding{
			ID:       "CONFUSABLE_FILENAME",
			Severity: "high",
			File:     filepath.ToSlash(relPath),
			Line:     1,
			Summary:  "filename mixes ASCII with confusable non-ASCII characters",
		})
	}
	return findings
}

func hasMixedScriptLetters(name string) bool {
	scripts := make(map[string]struct{}, 2)
	for _, r := range name {
		if !unicode.IsLetter(r) {
			continue
		}
		if script, ok := runeScriptGroup(r); ok {
			scripts[script] = struct{}{}
			if len(scripts) > 1 {
				return true
			}
		}
	}
	return false
}

func hasASCIIConfusableFilename(name string) bool {
	hasASCIIAlnum := false
	hasNonASCIIConfusable := false
	for _, r := range name {
		if r <= unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			hasASCIIAlnum = true
			continue
		}
		if _, ok := confusableFilenameRunes[r]; ok || isFullwidthASCIIConfusable(r) {
			hasNonASCIIConfusable = true
		}
	}
	return hasASCIIAlnum && hasNonASCIIConfusable
}

func isFullwidthASCIIConfusable(r rune) bool {
	switch {
	case r >= '０' && r <= '９':
		return true
	case r >= 'Ａ' && r <= 'Ｚ':
		return true
	case r >= 'ａ' && r <= 'ｚ':
		return true
	default:
		return false
	}
}

func runeScriptGroup(r rune) (string, bool) {
	switch {
	case unicode.In(r, unicode.Latin):
		return "Latin", true
	case unicode.In(r, unicode.Cyrillic):
		return "Cyrillic", true
	case unicode.In(r, unicode.Greek):
		return "Greek", true
	case unicode.In(r, unicode.Han):
		return "Han", true
	case unicode.In(r, unicode.Hiragana):
		return "Hiragana", true
	case unicode.In(r, unicode.Katakana):
		return "Katakana", true
	case unicode.In(r, unicode.Hangul):
		return "Hangul", true
	case unicode.In(r, unicode.Arabic):
		return "Arabic", true
	case unicode.In(r, unicode.Hebrew):
		return "Hebrew", true
	case unicode.In(r, unicode.Devanagari):
		return "Devanagari", true
	default:
		return "", false
	}
}

func scanTargets(skillRoot string) ([]scanTarget, error) {
	rootInfo, rootErr := os.Lstat(skillRoot)
	if rootErr != nil {
		return nil, fmt.Errorf("failed walking skill files for scan: %w", rootErr)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("failed walking skill files for scan: %s: scan source root must not be a symlink: %s", ruleScanSymlinkInSource, skillRoot)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("failed walking skill files for scan: %s: scan source root must be a directory: %s", ruleScanSpecialFile, skillRoot)
	}

	entries := make([]scanTarget, 0, 16)
	scannedFiles := 0
	err := filepath.WalkDir(skillRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(skillRoot, path)
		if err != nil {
			return fmt.Errorf("failed to compute relative path for scan: %w", err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: scan source contains symlink: %s", ruleScanSymlinkInSource, rel)
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := os.Lstat(path)
		if infoErr != nil {
			return fmt.Errorf("failed to stat scan source file: %w", infoErr)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: scan source contains non-regular file: %s", ruleScanSpecialFile, rel)
		}
		scannedFiles++
		if scannedFiles > scanMaxFiles {
			return fmt.Errorf("%s: scan source exceeded max file count: %d", ruleScanFileCount, scanMaxFiles)
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".md") {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "markdown",
				Info:     info,
			})
			return nil
		}
		ext := strings.ToLower(filepath.Ext(lower))
		if _, ok := scriptLikeExtensions[ext]; ok {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "script",
				Info:     info,
			})
			return nil
		}
		if _, ok := manifestLikeFiles[lower]; ok {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "manifest",
				Info:     info,
			})
			return nil
		}
		isShebangScript, probeErr := hasScriptShebang(path)
		if probeErr != nil {
			return fmt.Errorf("failed to inspect scan source file type: %w", probeErr)
		}
		if info.Mode()&0o111 != 0 || isShebangScript {
			entries = append(entries, scanTarget{
				Absolute: path,
				Relative: rel,
				Kind:     "script",
				Info:     info,
			})
			return nil
		}
		entries = append(entries, scanTarget{
			Absolute: path,
			Relative: rel,
			Kind:     "unknown",
			Info:     info,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed walking skill files for scan: %w", err)
	}
	return entries, nil
}

func hasScriptShebang(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, maxShebangProbeBytes)
	n, readErr := f.Read(buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, readErr
	}
	if n == 0 {
		return false, nil
	}

	content := string(buf[:n])
	content = strings.TrimLeft(content, " \t")
	return strings.HasPrefix(content, "#!"), nil
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
			return []Finding{{
				ID:       "LARGE_TEXT_FILE",
				Severity: "medium",
				File:     target.Relative,
				Line:     1,
				Summary:  "text file exceeds scan size limit",
			}}, nil
		}
		return nil, fmt.Errorf("failed to read scan file %s: %w", target.Relative, err)
	}
	content := contentBuf.Bytes()

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	findings := make([]Finding, 0)
	for i, line := range lines {
		lineNum := i + 1
		if strings.TrimSpace(line) == "" {
			continue
		}

		normalized, changed := normalizeLineNFKC(line)
		if changed {
			findings = append(findings, Finding{
				ID:       "NFKC_CHANGES_TEXT",
				Severity: "medium",
				File:     target.Relative,
				Line:     lineNum,
				Summary:  "Unicode compatibility normalization changes text",
			})
		}
		for _, variant := range scanLineVariants(lines, i, line, normalized, changed) {
			findings = append(findings, scanVariantThreatFindings(variant, target, lineNum)...)
			findings = append(findings, scanDecodedVariantThreatFindings(variant, target, lineNum, 0)...)
		}
		findings = append(findings, classifyUnicodeThreats(line, target.Relative, lineNum)...)
	}

	return deduplicateFindings(findings), nil
}

func scanVariantThreatFindings(variant string, target scanTarget, lineNum int) []Finding {
	findings := make([]Finding, 0, 8)
	if curlPipePattern.MatchString(variant) || curlSubshellExecPattern.MatchString(variant) || curlBacktickExecPattern.MatchString(variant) || curlDotSubshellExecPattern.MatchString(variant) || curlDotBacktickExecPattern.MatchString(variant) || powerShellRemoteEvalPattern.MatchString(variant) || powerShellFetchEvalPattern.MatchString(variant) || pythonRemoteExecPattern.MatchString(variant) || nodeRemoteEvalPattern.MatchString(variant) || nodeRemoteFunctionExecPattern.MatchString(variant) || rubyRemoteEvalPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "CURL_PIPE_SHELL",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "network output reaches shell/interpreter execution",
		})
	}
	if base64PipeExec.MatchString(variant) || base64SubshellExec.MatchString(variant) || base64DotSubshellExec.MatchString(variant) || powerShellFromBase64ExecPattern.MatchString(variant) || pythonBase64ExecPattern.MatchString(variant) || nodeBase64EvalPattern.MatchString(variant) || perlBase64EvalPattern.MatchString(variant) || rubyBase64EvalPattern.MatchString(variant) {
		findings = append(findings, Finding{
			ID:       "BASE64_PIPE_EXEC",
			Severity: "critical",
			File:     target.Relative,
			Line:     lineNum,
			Summary:  "decoded payload reaches interpreter execution",
		})
	}
	if hexPipeExec.MatchString(variant) || hexSubshellExec.MatchString(variant) || hexDotSubshellExec.MatchString(variant) || powerShellFromHexExecPattern.MatchString(variant) || pythonHexExecPattern.MatchString(variant) || nodeHexEvalPattern.MatchString(variant) || perlHexEvalPattern.MatchString(variant) || rubyHexEvalPattern.MatchString(variant) {
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

func scanDecodedVariantThreatFindings(line string, target scanTarget, lineNum int, depth int) []Finding {
	if depth >= maxDecodedRecursionDepth {
		return nil
	}
	candidates := extractEncodedCandidates(line)
	if len(candidates) == 0 {
		return nil
	}

	findings := make([]Finding, 0, 4)
	for _, candidate := range candidates {
		decoded, ok := decodeCandidatePayload(candidate)
		if !ok || len(decoded) == 0 || len(decoded) > maxDecodedArtifactBytes {
			continue
		}
		if !isLikelyTextPayload(decoded) {
			continue
		}

		decodedText := strings.ReplaceAll(string(decoded), "\r\n", "\n")
		for _, decodedLine := range strings.Split(decodedText, "\n") {
			if strings.TrimSpace(decodedLine) == "" {
				continue
			}
			normalized, changed := normalizeLineNFKC(decodedLine)
			if changed {
				findings = append(findings, Finding{
					ID:       "NFKC_CHANGES_TEXT",
					Severity: "medium",
					File:     target.Relative,
					Line:     lineNum,
					Summary:  "Unicode compatibility normalization changes text",
				})
			}
			findings = append(findings, classifyUnicodeThreats(decodedLine, target.Relative, lineNum)...)
			for _, variant := range lineVariants(decodedLine, normalized, changed) {
				findings = append(findings, scanVariantThreatFindings(variant, target, lineNum)...)
				findings = append(findings, scanDecodedVariantThreatFindings(variant, target, lineNum, depth+1)...)
			}
		}
	}
	return findings
}

func extractEncodedCandidates(line string) []encodedCandidate {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', ':', '(', ')', '[', ']', '{', '}', '<', '>', '|':
			return true
		default:
			return false
		}
	})
	if len(fields) == 0 {
		return nil
	}

	candidates := make([]encodedCandidate, 0, minInt(len(fields), maxDecodedCandidatesPerLine))
	for _, raw := range fields {
		token := sanitizeRuntimeToken(raw)
		if token == "" {
			continue
		}
		token = strings.TrimPrefix(strings.ToLower(token), "0x")
		if len(token) >= minHexCandidateLength && len(token)%2 == 0 && isHexToken(token) {
			candidates = append(candidates, encodedCandidate{kind: "hex", value: token})
			if len(candidates) >= maxDecodedCandidatesPerLine {
				break
			}
			continue
		}

		token = sanitizeRuntimeToken(raw)
		if len(token) >= minBase64CandidateLength && isBase64Token(token) {
			candidates = append(candidates, encodedCandidate{kind: "base64", value: token})
			if len(candidates) >= maxDecodedCandidatesPerLine {
				break
			}
		}
	}
	return candidates
}

func decodeCandidatePayload(candidate encodedCandidate) ([]byte, bool) {
	switch candidate.kind {
	case "hex":
		decoded, err := hex.DecodeString(candidate.value)
		if err != nil {
			return nil, false
		}
		return decoded, true
	case "base64":
		token := strings.TrimSpace(candidate.value)
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(token, "="))
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.URLEncoding.DecodeString(token)
		if err == nil {
			return decoded, true
		}
		decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
		if err == nil {
			return decoded, true
		}
		return nil, false
	default:
		return nil, false
	}
}

func isLikelyTextPayload(decoded []byte) bool {
	if len(decoded) == 0 {
		return false
	}
	if !utf8.Valid(decoded) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(decoded) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && !unicode.IsControl(r)) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return printable*100/total >= 80
}

func isHexToken(token string) bool {
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

func isBase64Token(token string) bool {
	if token == "" {
		return false
	}
	paddingStart := -1
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_':
		case c == '=':
			if paddingStart < 0 {
				paddingStart = i
			}
		default:
			return false
		}
		if paddingStart >= 0 && c != '=' {
			return false
		}
	}
	return true
}

func hasPromptOverrideApproximatePhrase(line string) bool {
	tokens := tokenizeWords(line)
	if len(tokens) == 0 {
		return false
	}
	for _, phrase := range promptOverridePhrases {
		if len(tokens) < len(phrase) {
			continue
		}
		for i := 0; i <= len(tokens)-len(phrase); i++ {
			if matchesApproximatePhrase(tokens[i:i+len(phrase)], phrase) {
				return true
			}
		}
	}
	return false
}

func matchesApproximatePhrase(window []string, phrase []string) bool {
	if len(window) != len(phrase) {
		return false
	}
	for i := range phrase {
		if !isApproxWordMatch(window[i], phrase[i]) {
			return false
		}
	}
	return true
}

func isApproxWordMatch(in string, want string) bool {
	if in == want {
		return true
	}
	if len(in) < 3 || len(want) < 3 {
		return false
	}
	if isTypoglycemiaVariant(in, want) {
		return true
	}
	return boundedLevenshteinDistance(in, want, 1) <= 1
}

func isTypoglycemiaVariant(in string, want string) bool {
	inRunes := []rune(in)
	wantRunes := []rune(want)
	if len(inRunes) != len(wantRunes) || len(inRunes) < 4 {
		return false
	}
	if inRunes[0] != wantRunes[0] || inRunes[len(inRunes)-1] != wantRunes[len(wantRunes)-1] {
		return false
	}
	inMiddle := make(map[rune]int, len(inRunes))
	wantMiddle := make(map[rune]int, len(wantRunes))
	for i := 1; i < len(inRunes)-1; i++ {
		inMiddle[inRunes[i]]++
		wantMiddle[wantRunes[i]]++
	}
	if len(inMiddle) != len(wantMiddle) {
		return false
	}
	for r, count := range inMiddle {
		if wantMiddle[r] != count {
			return false
		}
	}
	return true
}

func boundedLevenshteinDistance(a string, b string, limit int) int {
	ra := []rune(a)
	rb := []rune(b)
	if absInt(len(ra)-len(rb)) > limit {
		return limit + 1
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			insertCost := curr[j-1] + 1
			deleteCost := prev[j] + 1
			replaceCost := prev[j-1] + cost
			best := minInt(insertCost, deleteCost)
			best = minInt(best, replaceCost)
			curr[j] = best
			if best < rowMin {
				rowMin = best
			}
		}
		if rowMin > limit {
			return limit + 1
		}
		prev, curr = curr, prev
	}
	if prev[len(rb)] > limit {
		return limit + 1
	}
	return prev[len(rb)]
}

func hasChmodExecChain(line string) bool {
	segments := splitCommandSegments(line)
	if len(segments) < 2 {
		return false
	}
	targets := make(map[string]struct{}, 2)
	for _, segment := range segments {
		fields := strings.Fields(strings.TrimSpace(segment))
		if len(fields) == 0 {
			continue
		}

		if target := findChmodExecutableTarget(fields); target != "" {
			targets[target] = struct{}{}
			continue
		}

		execTarget := findExecutedLocalTarget(fields)
		if execTarget == "" {
			continue
		}
		if _, ok := targets[execTarget]; ok {
			return true
		}
	}
	return false
}

func splitCommandSegments(line string) []string {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	replacer := strings.NewReplacer("&&", ";", "||", ";")
	normalized := replacer.Replace(line)
	raw := strings.Split(normalized, ";")
	out := make([]string, 0, len(raw))
	for _, segment := range raw {
		trimmed := strings.TrimSpace(segment)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func findChmodExecutableTarget(fields []string) string {
	start := 0
	if fields[start] == "sudo" {
		start++
		if start >= len(fields) {
			return ""
		}
	}
	if fields[start] != "chmod" {
		return ""
	}
	for i := start + 1; i < len(fields)-1; i++ {
		if strings.Contains(fields[i], "+x") {
			return normalizeExecPath(fields[i+1])
		}
	}
	return ""
}

func findExecutedLocalTarget(fields []string) string {
	start := 0
	if fields[start] == "sudo" {
		start++
		if start >= len(fields) {
			return ""
		}
	}
	cmd := strings.ToLower(fields[start])
	switch cmd {
	case "chmod":
		return ""
	case "sh", "bash", "zsh", "pwsh", "powershell", "python", "node":
		if start+1 >= len(fields) {
			return ""
		}
		return normalizeExecPath(fields[start+1])
	default:
		return normalizeExecPath(fields[start])
	}
}

func normalizeExecPath(token string) string {
	clean := strings.TrimSpace(token)
	clean = strings.Trim(clean, `"'`)
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, ".\\")
	clean = strings.TrimSuffix(clean, ",")
	clean = strings.TrimSuffix(clean, ")")
	clean = strings.TrimSuffix(clean, "]")
	if clean == "" {
		return ""
	}
	if strings.HasPrefix(clean, "-") {
		return ""
	}
	if strings.Contains(clean, "://") {
		return ""
	}
	if strings.ContainsRune(clean, '$') {
		return ""
	}
	return clean
}

func hasHomeConfigWrite(line string) bool {
	lower := strings.ToLower(line)
	if hasCrontabWrite(lower) {
		return true
	}
	if !containsAnyString(lower, homeConfigPathHints) {
		return false
	}
	if strings.Contains(lower, ">>") || strings.Contains(lower, ">|") {
		return true
	}
	if strings.Contains(lower, "| tee") || strings.Contains(lower, "tee -a") {
		return true
	}
	if strings.Contains(lower, " cp ") || strings.HasPrefix(strings.TrimSpace(lower), "cp ") {
		return true
	}
	if strings.Contains(lower, " mv ") || strings.HasPrefix(strings.TrimSpace(lower), "mv ") {
		return true
	}
	if strings.Contains(lower, " install ") || strings.HasPrefix(strings.TrimSpace(lower), "install ") {
		return true
	}
	return false
}

func hasCrontabWrite(line string) bool {
	if strings.Contains(line, "| crontab") || strings.Contains(line, "|crontab") {
		return true
	}
	return strings.Contains(line, "crontab -e")
}

func containsAnyString(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func hasSecretExfilLine(line string) bool {
	lower := strings.ToLower(line)
	if !containsAnyString(lower, secretPathHints) {
		return false
	}
	if !secretExfilNetworkCommand.MatchString(lower) {
		return false
	}
	if !strings.Contains(lower, "http://") && !strings.Contains(lower, "https://") {
		return false
	}
	if strings.Contains(lower, "| curl") || strings.Contains(lower, "|curl") || strings.Contains(lower, "| wget") || strings.Contains(lower, "|wget") {
		return true
	}
	sendHints := []string{
		"-d ",
		"--data",
		"--upload-file",
		"requests.post",
		"invoke-restmethod",
		"invoke-webrequest",
		"-f ",
	}
	return containsAnyString(lower, sendHints)
}

func hasBashWildcardPermission(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "bash") {
		return false
	}
	for _, pattern := range bashWildcardPermissionPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

func hasEncodedCommandExecLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return false
	}

	sawPowerShell := false
	for _, field := range fields {
		token := sanitizeRuntimeToken(field)
		switch token {
		case "powershell", "pwsh", "powershell.exe", "pwsh.exe":
			sawPowerShell = true
			continue
		}
		if !sawPowerShell {
			continue
		}
		if isEncodedCommandFlagToken(token) {
			return true
		}
	}
	return false
}

func isEncodedCommandFlagToken(token string) bool {
	if token == "" {
		return false
	}
	trimmed := strings.TrimLeft(token, "-/")
	switch {
	case trimmed == "encodedcommand", trimmed == "enc":
		return true
	case strings.HasPrefix(trimmed, "encodedcommand:"), strings.HasPrefix(trimmed, "encodedcommand="):
		return true
	case strings.HasPrefix(trimmed, "enc:"), strings.HasPrefix(trimmed, "enc="):
		return true
	default:
		return false
	}
}

func tokenizeWords(line string) []string {
	normalized := strings.ToLower(strings.TrimSpace(line))
	if normalized == "" {
		return nil
	}
	words := strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	out := make([]string, 0, len(words))
	for _, word := range words {
		if word == "" {
			continue
		}
		out = append(out, word)
	}
	return out
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

func normalizeLineNFKC(line string) (string, bool) {
	if isASCII(line) {
		return line, false
	}
	normalized := norm.NFKC.String(line)
	return normalized, normalized != line
}

func lineVariants(raw string, normalized string, hasNormalized bool) []string {
	if !hasNormalized {
		return []string{raw}
	}
	return []string{raw, normalized}
}

func scanLineVariants(lines []string, idx int, raw string, normalized string, hasNormalized bool) []string {
	variants := lineVariants(raw, normalized, hasNormalized)
	joined, ok := buildContinuationVariant(lines, idx)
	if !ok {
		return variants
	}
	joinedNormalized, joinedChanged := normalizeLineNFKC(joined)
	return append(variants, lineVariants(joined, joinedNormalized, joinedChanged)...)
}

func buildContinuationVariant(lines []string, idx int) (string, bool) {
	if idx < 0 || idx >= len(lines) {
		return "", false
	}
	start := strings.TrimSpace(lines[idx])
	if !shouldJoinWithNextLine(start) {
		return "", false
	}

	parts := []string{start}
	joined := start
	added := 0
	for j := idx + 1; j < len(lines) && added < maxJoinedContinuationLines; j++ {
		next := strings.TrimSpace(lines[j])
		if next == "" {
			break
		}
		parts = append(parts, next)
		added++
		joined = strings.Join(parts, " ")
		if !shouldJoinWithNextLine(joined) {
			return joined, true
		}
	}
	if len(parts) > 1 {
		return strings.Join(parts, " "), true
	}
	return "", false
}

func shouldJoinWithNextLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	if strings.HasSuffix(trimmed, "\\") || strings.HasSuffix(trimmed, "|") || strings.HasSuffix(trimmed, "||") || strings.HasSuffix(trimmed, "&&") {
		return true
	}
	if strings.Contains(trimmed, "$(") && !strings.Contains(trimmed, ")") {
		return true
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

func isUnpinnedRuntimeToolLine(line string) bool {
	lowerLine := strings.ToLower(strings.TrimSpace(line))
	if isRemoteScriptImportLine(lowerLine) {
		return true
	}
	if isUnpinnedDenoNpmRuntimeLine(lowerLine) {
		return true
	}

	fields := strings.Fields(lowerLine)
	if len(fields) == 0 {
		return false
	}

	for i := 0; i < len(fields); i++ {
		token := normalizeLauncherToken(fields[i])
		if token == "corepack" {
			launcher, launcherIndex, ok := nextNonFlagFieldWithIndex(fields, i+1)
			if !ok {
				continue
			}
			launcher = normalizeLauncherToken(launcher)
			if isUnpinnedLauncherCommand(fields, launcher, launcherIndex) {
				return true
			}
			continue
		}

		if isUnpinnedLauncherCommand(fields, token, i) {
			return true
		}
	}

	return false
}

func normalizeLauncherToken(token string) string {
	token = strings.TrimSpace(strings.ToLower(sanitizeRuntimeToken(token)))
	if token == "" {
		return token
	}
	for _, launcher := range []string{"npx", "uvx", "bunx", "pnpm", "yarn", "npm"} {
		prefix := launcher + "@"
		if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
			return launcher
		}
	}
	return token
}

func sanitizeRuntimeToken(token string) string {
	token = strings.TrimSpace(token)
	return strings.Trim(token, "\"'`,;:()[]{}")
}

func isUnpinnedLauncherCommand(fields []string, token string, tokenIndex int) bool {
	switch token {
	case "npx", "uvx", "bunx":
		packageRefs := extractPackageRefsFromFlags(fields, tokenIndex+1, len(fields))
		if len(packageRefs) > 0 {
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}
		packageRef, ok := nextRuntimePackageCandidate(fields, tokenIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "pnpm", "yarn":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || subcommand != "dlx" {
			return false
		}

		packageRefs := extractPackageRefsFromFlags(fields, subcommandIndex+1, len(fields))
		if len(packageRefs) > 0 {
			if postSepRef, ok := nextExplicitPackageLikeTokenAfterSeparator(fields, subcommandIndex+1, len(fields)); ok {
				packageRefs = append(packageRefs, postSepRef)
			}
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}

		packageRef, ok := nextRuntimePackageCandidate(fields, subcommandIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "npm":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || subcommand != "exec" {
			return false
		}

		packageRefs := extractPackageRefsFromFlags(fields, subcommandIndex+1, len(fields))
		if len(packageRefs) > 0 {
			if postSepRef, ok := nextExplicitPackageLikeTokenAfterSeparator(fields, subcommandIndex+1, len(fields)); ok {
				packageRefs = append(packageRefs, postSepRef)
			}
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}

		packageRef, ok := nextRuntimePackageCandidate(fields, subcommandIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "go":
		runArgsStart, ok := findGoRunArgsStart(fields, tokenIndex)
		if !ok {
			return false
		}
		target, ok := nextGoRunTarget(fields, runArgsStart, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedGoRunTarget(target)
	default:
		return false
	}
}

func isUnpinnedGoRunTarget(target string) bool {
	if target == "" {
		return false
	}
	if strings.HasSuffix(target, ".go") {
		return false
	}
	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}
	if strings.HasPrefix(target, ".\\") || strings.HasPrefix(target, "..\\") || strings.HasPrefix(target, "\\") {
		return false
	}

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		if len(parts) != 2 {
			return false
		}
		version := strings.TrimSpace(parts[1])
		return !isPinnedGoModuleVersion(version)
	}

	// Remote Go module/package paths conventionally include a dot in the first segment.
	firstSegment := target
	if slash := strings.Index(firstSegment, "/"); slash >= 0 {
		firstSegment = firstSegment[:slash]
	}
	return strings.Contains(firstSegment, ".")
}

func isPinnedGoModuleVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	if goSemverExactPattern.MatchString(lower) {
		return true
	}
	if goPseudoVersionPattern.MatchString(lower) {
		return true
	}
	if hexCommitRefPattern.MatchString(lower) {
		return true
	}
	return false
}

func isRemoteScriptImportLine(lowerLine string) bool {
	if remoteScriptImportPattern.MatchString(lowerLine) {
		return true
	}
	if remoteScriptDotImport.MatchString(lowerLine) {
		return true
	}
	return remoteDenoRunPattern.MatchString(lowerLine)
}

func isUnpinnedPackageRef(ref string) bool {
	if ref == "" {
		return false
	}

	if strings.HasPrefix(ref, "@") {
		lastAt := strings.LastIndex(ref, "@")
		if lastAt <= 0 || lastAt == len(ref)-1 {
			return true
		}
		return !isPinnedPackageVersion(ref[lastAt+1:])
	}

	parts := strings.SplitN(ref, "@", 2)
	if len(parts) == 1 {
		return true
	}
	return !isPinnedPackageVersion(parts[1])
}

func isPinnedPackageVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	// Treat exact semver as pinned for package launchers. Dist-tags and ranges
	// like "next", "^1.2.3", or "~1.2.3" remain floating.
	return goSemverExactPattern.MatchString(lower)
}

func isUnpinnedDenoNpmRuntimeLine(lowerLine string) bool {
	fields := strings.Fields(lowerLine)
	if len(fields) < 2 || fields[0] != "deno" {
		return false
	}

	start := 1
	switch fields[1] {
	case "run", "x":
		start = 2
	}

	packageRefs := extractDenoNpmPackageRefs(fields, start, len(fields))
	if len(packageRefs) > 0 {
		for _, packageRef := range packageRefs {
			if isUnpinnedDenoRuntimeSpecifier(packageRef) {
				return true
			}
		}
		// When --package is present, still evaluate target specifiers.
		target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedDenoRuntimeSpecifier(target)
	}

	target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
	if !ok {
		return false
	}
	return isUnpinnedDenoRuntimeSpecifier(target)
}

func extractDenoNpmPackageRefs(fields []string, start int, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return nil
	}

	out := make([]string, 0, 2)
	for i := start; i < end; i++ {
		token := strings.ToLower(strings.TrimSpace(fields[i]))
		switch {
		case token == "--package" || token == "-p":
			if i+1 >= end {
				continue
			}
			next := sanitizeRuntimeToken(fields[i+1])
			if next == "" || strings.HasPrefix(next, "-") {
				continue
			}
			out = append(out, next)
			i++
		case strings.HasPrefix(token, "--package="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(fields[i], "--package="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(fields[i], "-p="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		}
	}
	return out
}

func nextDenoRuntimeTarget(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	flagNeedsValue := map[string]struct{}{
		"-c":           {},
		"--config":     {},
		"--import-map": {},
		"--location":   {},
		"--cert":       {},
		"--lock":       {},
		"--seed":       {},
		"--package":    {},
		"-p":           {},
	}
	flagOptionalKnownValue := map[string]struct{}{
		"--reload":           {},
		"-r":                 {},
		"--vendor":           {},
		"--node-modules-dir": {},
		"--allow-scripts":    {},
		"--allow-import":     {},
	}

	for i := start; i < end; i++ {
		token := strings.TrimSpace(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			lowerToken := strings.ToLower(token)
			if _, needsValue := flagNeedsValue[lowerToken]; needsValue {
				i++
				continue
			}
			if _, hasOptionalValue := flagOptionalKnownValue[lowerToken]; hasOptionalValue && i+1 < end {
				next := strings.ToLower(sanitizeRuntimeToken(fields[i+1]))
				if isKnownDenoOptionalFlagValue(lowerToken, next, fields, i+2, end) {
					i++
				}
			}
			continue
		}
		return sanitizeRuntimeToken(token), true
	}
	return "", false
}

func isKnownDenoOptionalFlagValue(
	flag string,
	value string,
	fields []string,
	nextStart int,
	end int,
) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	switch flag {
	case "--reload", "-r":
		// Avoid mistaking reload blocklist values for the runtime target only when
		// another candidate target exists later in the command.
		if !hasDenoRuntimeCandidateAfter(fields, nextStart, end) {
			return false
		}
		for _, part := range strings.Split(value, ",") {
			if !isDenoReloadBlocklistValue(strings.TrimSpace(part)) {
				return false
			}
		}
		return true
	case "--vendor":
		return value == "true" || value == "false"
	case "--node-modules-dir":
		switch value {
		case "auto", "manual", "none", "true", "false":
			return true
		}
	case "--allow-scripts":
		// Consume split allow-scripts values only when they are package-like
		// tokens and another runtime candidate follows.
		if !hasDenoRuntimeCandidateAfter(fields, nextStart, end) {
			return false
		}
		return isDenoAllowScriptsValue(value)
	case "--allow-import":
		// Consume split allow-import values only when they look like import
		// host/url allowlist entries and another runtime candidate follows.
		if !hasDenoRuntimeCandidateAfter(fields, nextStart, end) {
			return false
		}
		return isDenoAllowImportValue(value)
	}
	return false
}

func isDenoReloadBlocklistValue(value string) bool {
	if value == "" {
		return false
	}
	switch {
	case strings.HasPrefix(value, "npm:"):
		return true
	case strings.HasPrefix(value, "jsr:"):
		return true
	case strings.HasPrefix(value, "http://"), strings.HasPrefix(value, "https://"):
		return true
	case strings.HasPrefix(value, "file:"):
		return true
	case strings.HasPrefix(value, "./"), strings.HasPrefix(value, "../"), strings.HasPrefix(value, "/"):
		return true
	default:
		return false
	}
}

func isDenoAllowScriptsValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		// Keep allow-scripts split-value handling conservative: skip ambiguous
		// runtime specifier and path-like forms.
		if strings.Contains(token, ":") {
			return false
		}
		if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") ||
			strings.HasPrefix(token, "/") || strings.HasPrefix(token, ".\\") ||
			strings.HasPrefix(token, "..\\") || strings.HasPrefix(token, "\\") {
			return false
		}
		if !isScopedOrPackageRefToken(token) {
			return false
		}
	}
	return true
}

func isDenoAllowImportValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		if strings.HasPrefix(token, "https://") || strings.HasPrefix(token, "http://") {
			continue
		}
		if isHostLikeToken(token) {
			continue
		}
		return false
	}
	return true
}

func isHostLikeToken(token string) bool {
	host := token
	if strings.HasPrefix(host, "[") {
		// IPv6 host forms for allowlist values.
		endBracket := strings.Index(host, "]")
		if endBracket < 0 {
			return false
		}
		if endBracket+1 < len(host) {
			if host[endBracket+1] != ':' {
				return false
			}
			if endBracket+2 >= len(host) {
				return false
			}
		}
		return true
	}
	host = strings.TrimPrefix(host, "*.")
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		if idx == len(host)-1 {
			return false
		}
		for i := idx + 1; i < len(host); i++ {
			if host[i] < '0' || host[i] > '9' {
				return false
			}
		}
		host = host[:idx]
	}
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		ch := host[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '.', ch == '-':
		default:
			return false
		}
	}
	return true
}

func isScopedOrPackageRefToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		ch := token[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '@', ch == '/', ch == '.', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

func hasDenoRuntimeCandidateAfter(fields []string, start int, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return false
	}

	flagNeedsValue := map[string]struct{}{
		"-c":           {},
		"--config":     {},
		"--import-map": {},
		"--location":   {},
		"--cert":       {},
		"--lock":       {},
		"--seed":       {},
		"--package":    {},
		"-p":           {},
	}

	for i := start; i < end; i++ {
		token := strings.TrimSpace(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return true
			}
			return false
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			lowerToken := strings.ToLower(token)
			if _, needsValue := flagNeedsValue[lowerToken]; needsValue {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func isUnpinnedDenoNpmSpecifier(ref string) bool {
	ref = strings.TrimSpace(sanitizeRuntimeToken(ref))
	if !strings.HasPrefix(ref, "npm:") {
		return false
	}
	spec := strings.TrimPrefix(ref, "npm:")
	if spec == "" {
		return false
	}
	if strings.HasPrefix(spec, "@") {
		scopeSlash := strings.Index(spec, "/")
		if scopeSlash < 0 {
			return true
		}
		lastAt := strings.LastIndex(spec, "@")
		if lastAt <= scopeSlash || lastAt == len(spec)-1 {
			return true
		}
		version := spec[lastAt+1:]
		if slash := strings.Index(version, "/"); slash >= 0 {
			version = version[:slash]
		}
		if version == "" {
			return true
		}
		return !isPinnedPackageVersion(version)
	}

	at := strings.Index(spec, "@")
	if at < 0 {
		return true
	}
	version := spec[at+1:]
	if slash := strings.Index(version, "/"); slash >= 0 {
		version = version[:slash]
	}
	if version == "" {
		return true
	}
	return !isPinnedPackageVersion(version)
}

func isUnpinnedDenoRuntimeSpecifier(ref string) bool {
	return isUnpinnedDenoNpmSpecifier(ref) || isUnpinnedDenoJSRSpecifier(ref)
}

func isUnpinnedDenoJSRSpecifier(ref string) bool {
	ref = strings.TrimSpace(sanitizeRuntimeToken(ref))
	if !strings.HasPrefix(ref, "jsr:") {
		return false
	}
	spec := strings.TrimPrefix(ref, "jsr:")
	if spec == "" {
		return false
	}

	if strings.HasPrefix(spec, "@") {
		scopeSlash := strings.Index(spec, "/")
		if scopeSlash < 0 {
			return true
		}
		lastAt := strings.LastIndex(spec, "@")
		if lastAt <= scopeSlash || lastAt == len(spec)-1 {
			return true
		}
		version := spec[lastAt+1:]
		if slash := strings.Index(version, "/"); slash >= 0 {
			version = version[:slash]
		}
		if version == "" {
			return true
		}
		return !isPinnedPackageVersion(version)
	}

	at := strings.Index(spec, "@")
	if at < 0 {
		return true
	}
	version := spec[at+1:]
	if slash := strings.Index(version, "/"); slash >= 0 {
		version = version[:slash]
	}
	if version == "" {
		return true
	}
	return !isPinnedPackageVersion(version)
}

func nextNonFlagFieldWithIndex(fields []string, start int) (string, int, bool) {
	for i := start; i < len(fields); i++ {
		if strings.HasPrefix(fields[i], "-") {
			continue
		}
		return fields[i], i, true
	}
	return "", -1, false
}

func extractPackageRefsFromFlags(fields []string, start int, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return nil
	}

	out := make([]string, 0, 2)
	for i := start; i < end; i++ {
		token := strings.ToLower(strings.TrimSpace(fields[i]))
		switch {
		case token == "--package" || token == "-p":
			if i+1 >= end {
				continue
			}
			next := sanitizeRuntimeToken(fields[i+1])
			if next == "" || strings.HasPrefix(next, "-") {
				continue
			}
			out = append(out, next)
			i++
		case strings.HasPrefix(token, "--package="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(fields[i], "--package="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(fields[i], "-p="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		}
	}
	return out
}

func nextRuntimePackageCandidate(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	for i := start; i < end; i++ {
		token := strings.ToLower(strings.TrimSpace(fields[i]))
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if token == "-c" || token == "--call" {
			return "", false
		}
		if token == "-p" || token == "--package" {
			i++
			continue
		}
		if strings.HasPrefix(token, "-c=") || strings.HasPrefix(token, "--call=") {
			return "", false
		}
		if strings.HasPrefix(token, "-p=") || strings.HasPrefix(token, "--package=") {
			continue
		}
		if strings.HasPrefix(token, "-") {
			continue
		}
		return fields[i], true
	}
	return "", false
}

func nextExplicitPackageLikeTokenAfterSeparator(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	for i := start; i < end; i++ {
		if strings.TrimSpace(fields[i]) != "--" {
			continue
		}
		for j := i + 1; j < end; j++ {
			candidate := sanitizeRuntimeToken(fields[j])
			if candidate == "" {
				continue
			}
			if isExplicitPackageLikeRef(candidate) {
				return candidate, true
			}
			return "", false
		}
		return "", false
	}
	return "", false
}

func isExplicitPackageLikeRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.HasPrefix(ref, "@") {
		return true
	}
	if strings.Contains(ref, "@") {
		return true
	}
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, ".\\") || strings.HasPrefix(ref, "..\\") || strings.HasPrefix(ref, "\\") {
		return false
	}
	return strings.Contains(ref, "/")
}

func findGoRunArgsStart(fields []string, tokenIndex int) (int, bool) {
	if tokenIndex < 0 || tokenIndex >= len(fields) {
		return -1, false
	}
	for i := tokenIndex + 1; i < len(fields); i++ {
		token := strings.TrimSpace(fields[i])
		if token == "" {
			continue
		}
		if token == "run" {
			if i+1 >= len(fields) {
				return -1, false
			}
			return i + 1, true
		}
		// `go -C <dir> run ...` is a common pre-subcommand form.
		if token == "-c" || token == "-C" {
			i++
			continue
		}
		if strings.HasPrefix(token, "-c=") || strings.HasPrefix(token, "-C=") {
			continue
		}
		if strings.HasPrefix(token, "-") {
			// Unknown pre-subcommand flags are treated as non-match.
			return -1, false
		}
		// Another subcommand (`go test`, `go build`, etc.)
		return -1, false
	}
	return -1, false
}

func nextGoRunTarget(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	flagNeedsValue := map[string]struct{}{
		"-mod":      {},
		"-modfile":  {},
		"-exec":     {},
		"-overlay":  {},
		"-p":        {},
		"-tags":     {},
		"-toolexec": {},
	}

	for i := start; i < end; i++ {
		token := strings.TrimSpace(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			if _, needsValue := flagNeedsValue[token]; needsValue {
				i++
			}
			continue
		}
		return sanitizeRuntimeToken(token), true
	}
	return "", false
}

func classifyURLRisks(line string, relPath string, lineNum int, isMarkdown bool) []Finding {
	matches := urlPattern.FindAllString(line, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, raw := range matches {
		parsed, err := neturl.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			out = append(out, Finding{
				ID:       "RAW_IP_URL",
				Severity: "high",
				File:     relPath,
				Line:     lineNum,
				Summary:  "URL points to a raw IP host",
			})
		}
		if _, ok := urlShortenerHosts[host]; ok {
			out = append(out, Finding{
				ID:       "URL_SHORTENER",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "URL shortener host detected",
			})
		}
		if _, ok := pasteSiteHosts[host]; ok {
			out = append(out, Finding{
				ID:       "PASTE_SITE_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "paste site URL detected",
			})
		}
		if host == "github.com" && strings.Contains(strings.ToLower(parsed.Path), "/releases/download/") {
			out = append(out, Finding{
				ID:       "RELEASE_ASSET_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "release asset URL detected",
			})
		}
		if isMarkdown && isRemoteImageLine(line) && isImagePath(parsed.Path) {
			out = append(out, Finding{
				ID:       "REMOTE_IMAGE_URL",
				Severity: "medium",
				File:     relPath,
				Line:     lineNum,
				Summary:  "remote image URL detected in markdown content",
			})
		}
	}
	return out
}

func isRemoteImageLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(line, "![") || strings.Contains(lower, "<img")
}

func isImagePath(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".png") ||
		strings.HasSuffix(lower, ".jpg") ||
		strings.HasSuffix(lower, ".jpeg") ||
		strings.HasSuffix(lower, ".gif") ||
		strings.HasSuffix(lower, ".webp") ||
		strings.HasSuffix(lower, ".svg") ||
		strings.HasSuffix(lower, ".bmp") ||
		strings.HasSuffix(lower, ".ico")
}

func classifyUnicodeThreats(line string, relPath string, lineNum int) []Finding {
	out := make([]Finding, 0, 6)
	hasUnicodeTag := false
	hasBidi := false
	hasZeroWidth := false
	hasControl := false
	hasVariationSelector := false
	hasANSIOSC := false

	if hasANSIOSCEscape(line) {
		hasANSIOSC = true
		out = append(out, Finding{
			ID:       "ANSI_OSC_ESCAPE_IN_TEXT",
			Severity: "critical",
			File:     relPath,
			Line:     lineNum,
			Summary:  "ANSI/OSC escape sequence detected in text",
		})
	}

	for _, r := range line {
		if !hasUnicodeTag && r >= 0xE0000 && r <= 0xE007F {
			hasUnicodeTag = true
			out = append(out, Finding{
				ID:       "UNICODE_TAG_IN_INSTRUCTIONS",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "Unicode Tags detected in text",
			})
		}
		if !hasBidi && isBidiControlRune(r) {
			hasBidi = true
			out = append(out, Finding{
				ID:       "BIDI_CONTROL_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "bidi control character detected in text",
			})
		}
		if !hasVariationSelector && isVariationSelectorRune(r) {
			hasVariationSelector = true
			out = append(out, Finding{
				ID:       "VARIATION_SELECTOR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "variation selector detected in text",
			})
		}
		if !hasZeroWidth && isZeroWidthRune(r) {
			hasZeroWidth = true
			out = append(out, Finding{
				ID:       "ZERO_WIDTH_CHAR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "zero-width character detected in text",
			})
		}
		if !hasControl && isDisallowedControlRune(r) {
			hasControl = true
			out = append(out, Finding{
				ID:       "CONTROL_CHAR_IN_TEXT",
				Severity: "critical",
				File:     relPath,
				Line:     lineNum,
				Summary:  "disallowed control character detected in text",
			})
		}
		if hasUnicodeTag && hasBidi && hasZeroWidth && hasControl && hasVariationSelector && hasANSIOSC {
			break
		}
	}

	return out
}

func isBidiControlRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isZeroWidthRune(r rune) bool {
	return (r >= 0x200B && r <= 0x200F) || r == 0x2060 || r == 0xFEFF
}

func isDisallowedControlRune(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return (r >= 0x00 && r <= 0x1F) || (r >= 0x7F && r <= 0x9F)
}

func isVariationSelectorRune(r rune) bool {
	return (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF)
}

func hasANSIOSCEscape(line string) bool {
	return strings.Contains(line, "\x1b[") || strings.Contains(line, "\x1b]")
}

func classifyMarkdownLinkSpoofing(line string, relPath string, lineNum int) []Finding {
	matches := markdownLinkPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]Finding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		displayHost, ok := parseDisplayLinkHost(match[1])
		if !ok {
			continue
		}
		targetHost, ok := parseURLHost(match[2])
		if !ok {
			continue
		}
		if normalizeHost(displayHost) == normalizeHost(targetHost) {
			continue
		}
		out = append(out, Finding{
			ID:       "LINK_SPOOFING_URL_MISMATCH",
			Severity: "high",
			File:     relPath,
			Line:     lineNum,
			Summary:  "markdown link label host differs from link target host",
		})
	}
	return out
}

func parseDisplayLinkHost(label string) (string, bool) {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" || strings.Contains(trimmed, " ") {
		return "", false
	}
	if strings.Contains(trimmed, "://") {
		return parseURLHost(trimmed)
	}
	if !strings.Contains(trimmed, ".") {
		return "", false
	}
	return parseURLHost("https://" + trimmed)
}

func parseURLHost(raw string) (string, bool) {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	return host, true
}

func normalizeHost(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(host))
	normalized = strings.TrimPrefix(normalized, "www.")
	return normalized
}

func deduplicateFindings(in []Finding) []Finding {
	seen := make(map[string]struct{}, len(in))
	out := make([]Finding, 0, len(in))
	for _, finding := range in {
		key := fmt.Sprintf("%s|%s|%d|%s", finding.ID, finding.File, finding.Line, finding.Severity)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

// IsRejectable returns true when finding severity should reject under strict mode.
func IsRejectable(f Finding) bool {
	return f.Severity == "critical" || f.Severity == "high"
}
