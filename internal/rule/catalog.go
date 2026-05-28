package rule

// Severity is the default severity assigned to a rule in the central catalog.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rule describes one scanner or guard rule ID.
type Rule struct {
	ID          string
	Severity    Severity
	Description string
}

var (
	ANSIOSCEscapeInText = Rule{
		ID:          "ANSI_OSC_ESCAPE_IN_TEXT",
		Severity:    SeverityCritical,
		Description: "ANSI/OSC escape sequence detected in text",
	}
	UnicodeTagInInstructions = Rule{
		ID:          "UNICODE_TAG_IN_INSTRUCTIONS",
		Severity:    SeverityCritical,
		Description: "Unicode Tags in instruction text",
	}
	BidiControlInText = Rule{
		ID:          "BIDI_CONTROL_IN_TEXT",
		Severity:    SeverityCritical,
		Description: "bidi override or isolate controls in text",
	}
	VariationSelectorInText = Rule{
		ID:          "VARIATION_SELECTOR_IN_TEXT",
		Severity:    SeverityCritical,
		Description: "variation selector detected in text",
	}
	ZeroWidthCharInText = Rule{
		ID:          "ZERO_WIDTH_CHAR_IN_TEXT",
		Severity:    SeverityCritical,
		Description: "zero-width character detected in text",
	}
	ControlCharInText = Rule{
		ID:          "CONTROL_CHAR_IN_TEXT",
		Severity:    SeverityCritical,
		Description: "disallowed control character detected in text",
	}
	NFKCChangesText = Rule{
		ID:          "NFKC_CHANGES_TEXT",
		Severity:    SeverityMedium,
		Description: "Unicode compatibility normalization changes text",
	}
	UnknownFileType = Rule{
		ID:          "UNKNOWN_FILE_TYPE",
		Severity:    SeverityMedium,
		Description: "binary or unclassified file",
	}
	LargeTextFile = Rule{
		ID:          "LARGE_TEXT_FILE",
		Severity:    SeverityMedium,
		Description: "unusually large text file for scan",
	}
	NonUTF8Text = Rule{
		ID:          "NON_UTF8_TEXT",
		Severity:    SeverityHigh,
		Description: "text scan input must be valid UTF-8",
	}
	CurlPipeShell = Rule{
		ID:          "CURL_PIPE_SHELL",
		Severity:    SeverityCritical,
		Description: "network fetch output reaches shell, interpreter, or eval",
	}
	Base64PipeExec = Rule{
		ID:          "BASE64_PIPE_EXEC",
		Severity:    SeverityCritical,
		Description: "decoded payload reaches shell, interpreter, or eval",
	}
	HexPipeExec = Rule{
		ID:          "HEX_PIPE_EXEC",
		Severity:    SeverityCritical,
		Description: "hex-decoded payload reaches shell, interpreter, or eval",
	}
	EncodedCommandExec = Rule{
		ID:          "ENCODED_COMMAND_EXEC",
		Severity:    SeverityCritical,
		Description: "encoded command execution flag detected",
	}
	ChmodExecChain = Rule{
		ID:          "CHMOD_EXEC_CHAIN",
		Severity:    SeverityCritical,
		Description: "chmod +x followed by execution of the same local artifact",
	}
	WritesHomeConfig = Rule{
		ID:          "WRITES_HOME_CONFIG",
		Severity:    SeverityHigh,
		Description: "writes to shell rc, ssh, cron, launch agents, or similar",
	}
	SecretExfil = Rule{
		ID:          "SECRET_EXFIL",
		Severity:    SeverityCritical,
		Description: "secret read combined with network send",
	}
	AllowedToolsBashWildcard = Rule{
		ID:          "ALLOWED_TOOLS_BASH_WILDCARD",
		Severity:    SeverityHigh,
		Description: "broad Bash or wildcard tool permission",
	}
	UnpinnedRuntimeTool = Rule{
		ID:          "UNPINNED_RUNTIME_TOOL",
		Severity:    SeverityHigh,
		Description: "floating runtime tool execution",
	}
	FakePrereqExecution = Rule{
		ID:          "FAKE_PREREQ_EXECUTION",
		Severity:    SeverityCritical,
		Description: "prerequisite language plus download/run instruction",
	}
	ExternalBinaryDownload = Rule{
		ID:          "EXTERNAL_BINARY_DOWNLOAD",
		Severity:    SeverityHigh,
		Description: "release asset or binary download instruction",
	}
	PromptOverrideLanguage = Rule{
		ID:          "PROMPT_OVERRIDE_LANGUAGE",
		Severity:    SeverityHigh,
		Description: "instruction text asks to ignore or override prior prompts",
	}
	PasswordProtectedArchive = Rule{
		ID:          "PASSWORD_PROTECTED_ARCHIVE",
		Severity:    SeverityHigh,
		Description: "password-protected archive instruction",
	}
	RawHTMLMarkup = Rule{
		ID:          "RAW_HTML_MARKUP",
		Severity:    SeverityMedium,
		Description: "raw HTML markup in markdown",
	}
	MixedScriptFilename = Rule{
		ID:          "MIXED_SCRIPT_FILENAME",
		Severity:    SeverityMedium,
		Description: "filename uses mixed scripts",
	}
	ConfusableFilename = Rule{
		ID:          "CONFUSABLE_FILENAME",
		Severity:    SeverityHigh,
		Description: "filename or directory name mixes ASCII with confusable non-ASCII homoglyphs",
	}
	LinkSpoofingURLMismatch = Rule{
		ID:          "LINK_SPOOFING_URL_MISMATCH",
		Severity:    SeverityHigh,
		Description: "markdown link display host differs from actual link target host",
	}
	RawIPURL = Rule{
		ID:          "RAW_IP_URL",
		Severity:    SeverityHigh,
		Description: "URL host is an IP address",
	}
	URLShortener = Rule{
		ID:          "URL_SHORTENER",
		Severity:    SeverityMedium,
		Description: "shortener URL",
	}
	PasteSiteURL = Rule{
		ID:          "PASTE_SITE_URL",
		Severity:    SeverityMedium,
		Description: "paste-site URL",
	}
	ReleaseAssetURL = Rule{
		ID:          "RELEASE_ASSET_URL",
		Severity:    SeverityMedium,
		Description: "GitHub release asset URL",
	}
	RemoteImageURL = Rule{
		ID:          "REMOTE_IMAGE_URL",
		Severity:    SeverityMedium,
		Description: "remote Markdown image URL",
	}
	SymlinkInScanSource = Rule{
		ID:          "SYMLINK_IN_SCAN_SOURCE",
		Severity:    SeverityHigh,
		Description: "scan source contains a symlink",
	}
	ScanFileCountExceeded = Rule{
		ID:          "SCAN_FILE_COUNT_EXCEEDED",
		Severity:    SeverityHigh,
		Description: "scan source exceeds maximum file count",
	}
	SpecialFileInScanSource = Rule{
		ID:          "SPECIAL_FILE_IN_SCAN_SOURCE",
		Severity:    SeverityHigh,
		Description: "scan source contains a non-regular file",
	}
	ScanSourceChangedDuringRead = Rule{
		ID:          "SCAN_SOURCE_CHANGED_DURING_READ",
		Severity:    SeverityHigh,
		Description: "scan source changed while being read",
	}
	FetchOutputSymlink = Rule{
		ID:          "FETCH_OUTPUT_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "fetch output root is a symlink",
	}
	FetchOutputEntrySymlink = Rule{
		ID:          "FETCH_OUTPUT_ENTRY_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "fetch output entry is a symlink",
	}
)

var catalog = []Rule{
	ANSIOSCEscapeInText,
	UnicodeTagInInstructions,
	BidiControlInText,
	VariationSelectorInText,
	ZeroWidthCharInText,
	ControlCharInText,
	NFKCChangesText,
	UnknownFileType,
	LargeTextFile,
	NonUTF8Text,
	CurlPipeShell,
	Base64PipeExec,
	HexPipeExec,
	EncodedCommandExec,
	ChmodExecChain,
	WritesHomeConfig,
	SecretExfil,
	AllowedToolsBashWildcard,
	UnpinnedRuntimeTool,
	FakePrereqExecution,
	ExternalBinaryDownload,
	PromptOverrideLanguage,
	PasswordProtectedArchive,
	RawHTMLMarkup,
	MixedScriptFilename,
	ConfusableFilename,
	LinkSpoofingURLMismatch,
	RawIPURL,
	URLShortener,
	PasteSiteURL,
	ReleaseAssetURL,
	RemoteImageURL,
	SymlinkInScanSource,
	ScanFileCountExceeded,
	SpecialFileInScanSource,
	ScanSourceChangedDuringRead,
	FetchOutputSymlink,
	FetchOutputEntrySymlink,
}

var catalogByID = buildCatalogByID(catalog)

// Lookup returns the registered rule for id.
func Lookup(id string) (Rule, bool) {
	r, ok := catalogByID[id]
	return r, ok
}

func buildCatalogByID(rules []Rule) map[string]Rule {
	out := make(map[string]Rule, len(rules))
	for _, r := range rules {
		out[r.ID] = r
	}
	return out
}
