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
	GitHubArchiveSchemeInvalid = Rule{
		ID:          "GITHUB_ARCHIVE_SCHEME_INVALID",
		Severity:    SeverityHigh,
		Description: "GitHub archive URL uses an invalid scheme",
	}
	GitHubArchiveRedirectHostMismatch = Rule{
		ID:          "GITHUB_ARCHIVE_REDIRECT_HOST_MISMATCH",
		Severity:    SeverityHigh,
		Description: "GitHub archive redirect changed host",
	}
	GitHubArchiveRedirectPortMismatch = Rule{
		ID:          "GITHUB_ARCHIVE_REDIRECT_PORT_MISMATCH",
		Severity:    SeverityHigh,
		Description: "GitHub archive redirect changed port",
	}
	GitHubArchiveRedirectSchemeInvalid = Rule{
		ID:          "GITHUB_ARCHIVE_REDIRECT_SCHEME_INVALID",
		Severity:    SeverityHigh,
		Description: "GitHub archive redirect changed scheme",
	}
	GitHubArchiveRedirectUserinfoDisallowed = Rule{
		ID:          "GITHUB_ARCHIVE_REDIRECT_USERINFO_DISALLOWED",
		Severity:    SeverityHigh,
		Description: "GitHub archive redirect included userinfo",
	}
	GitHubArchiveContentTypeInvalid = Rule{
		ID:          "GITHUB_ARCHIVE_CONTENT_TYPE_INVALID",
		Severity:    SeverityHigh,
		Description: "GitHub archive response content type is invalid",
	}
	GitHubArchiveContentEncodingInvalid = Rule{
		ID:          "GITHUB_ARCHIVE_CONTENT_ENCODING_INVALID",
		Severity:    SeverityHigh,
		Description: "GitHub archive response content encoding is invalid",
	}
	SourceMetadataFileTooLarge = Rule{
		ID:          "SOURCE_METADATA_FILE_TOO_LARGE",
		Severity:    SeverityHigh,
		Description: "source metadata file exceeds the size limit",
	}
	SourceMetadataSymlink = Rule{
		ID:          "SOURCE_METADATA_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "source metadata path contains a symlink",
	}
	SourceMetadataSpecialFile = Rule{
		ID:          "SOURCE_METADATA_SPECIAL_FILE",
		Severity:    SeverityHigh,
		Description: "source metadata path is not a regular file",
	}
	SourceMetadataSourceChangedDuringRead = Rule{
		ID:          "SOURCE_METADATA_SOURCE_CHANGED_DURING_READ",
		Severity:    SeverityHigh,
		Description: "source metadata changed while being read",
	}
	SourceMetadataInvalidUTF8 = Rule{
		ID:          "SOURCE_METADATA_INVALID_UTF8",
		Severity:    SeverityHigh,
		Description: "source metadata must be valid UTF-8",
	}
	LockfileTooLarge = Rule{
		ID:          "LOCKFILE_TOO_LARGE",
		Severity:    SeverityHigh,
		Description: "install lockfile exceeds the size limit",
	}
	LockfileInvalidUTF8 = Rule{
		ID:          "LOCKFILE_INVALID_UTF8",
		Severity:    SeverityHigh,
		Description: "install lockfile must be valid UTF-8",
	}
	LockfileSymlink = Rule{
		ID:          "LOCKFILE_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "install lockfile path contains a symlink",
	}
	LockfileSpecialFile = Rule{
		ID:          "LOCKFILE_SPECIAL_FILE",
		Severity:    SeverityHigh,
		Description: "install lockfile path is not a regular file",
	}
	LockfileSourceChangedDuringRead = Rule{
		ID:          "LOCKFILE_SOURCE_CHANGED_DURING_READ",
		Severity:    SeverityHigh,
		Description: "install lockfile changed while being read",
	}
	InstallTargetSymlink = Rule{
		ID:          "INSTALL_TARGET_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "install target root is a symlink",
	}
	InstallTargetEntrySymlink = Rule{
		ID:          "INSTALL_TARGET_ENTRY_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "install target entry is a symlink",
	}
	InstallSourceFileCountExceeded = Rule{
		ID:          "INSTALL_SOURCE_FILE_COUNT_EXCEEDED",
		Severity:    SeverityHigh,
		Description: "install source exceeds maximum file count",
	}
	InstallSourceTotalBytesExceeded = Rule{
		ID:          "INSTALL_SOURCE_TOTAL_BYTES_EXCEEDED",
		Severity:    SeverityHigh,
		Description: "install source exceeds maximum total bytes",
	}
	InstallSourceFileTooLarge = Rule{
		ID:          "INSTALL_SOURCE_FILE_TOO_LARGE",
		Severity:    SeverityHigh,
		Description: "install source file exceeds the size limit",
	}
	InstallSourceSymlink = Rule{
		ID:          "INSTALL_SOURCE_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "install source contains a symlink",
	}
	InstallSourceSpecialFile = Rule{
		ID:          "INSTALL_SOURCE_SPECIAL_FILE",
		Severity:    SeverityHigh,
		Description: "install source contains a non-regular file",
	}
	InstallSourceChangedDuringCopy = Rule{
		ID:          "INSTALL_SOURCE_CHANGED_DURING_COPY",
		Severity:    SeverityHigh,
		Description: "install source changed while being copied",
	}
	InstallDigestSymlink = Rule{
		ID:          "INSTALL_DIGEST_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "digest input contains a symlink",
	}
	InstallDigestFileCountExceeded = Rule{
		ID:          "INSTALL_DIGEST_FILE_COUNT_EXCEEDED",
		Severity:    SeverityHigh,
		Description: "digest input exceeds maximum file count",
	}
	InstallDigestTotalBytesExceeded = Rule{
		ID:          "INSTALL_DIGEST_TOTAL_BYTES_EXCEEDED",
		Severity:    SeverityHigh,
		Description: "digest input exceeds maximum total bytes",
	}
	InstallDigestFileTooLarge = Rule{
		ID:          "INSTALL_DIGEST_FILE_TOO_LARGE",
		Severity:    SeverityHigh,
		Description: "digest input file exceeds the size limit",
	}
	InstallDigestSpecialFile = Rule{
		ID:          "INSTALL_DIGEST_SPECIAL_FILE",
		Severity:    SeverityHigh,
		Description: "digest input contains a non-regular file",
	}
	InstallDigestSourceChangedDuringHash = Rule{
		ID:          "INSTALL_DIGEST_SOURCE_CHANGED_DURING_HASH",
		Severity:    SeverityHigh,
		Description: "digest input changed while being hashed",
	}
	InstallReportTooLarge = Rule{
		ID:          "INSTALL_REPORT_TOO_LARGE",
		Severity:    SeverityHigh,
		Description: "install report exceeds the size limit",
	}
	InstallReportInvalidUTF8 = Rule{
		ID:          "INSTALL_REPORT_INVALID_UTF8",
		Severity:    SeverityHigh,
		Description: "install report must be valid UTF-8",
	}
	InstallReportSymlink = Rule{
		ID:          "INSTALL_REPORT_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "install report path contains a symlink",
	}
	InstallReportSpecialFile = Rule{
		ID:          "INSTALL_REPORT_SPECIAL_FILE",
		Severity:    SeverityHigh,
		Description: "install report path is not a regular file",
	}
	InstallReportSourceChangedDuringRead = Rule{
		ID:          "INSTALL_REPORT_SOURCE_CHANGED_DURING_READ",
		Severity:    SeverityHigh,
		Description: "install report changed while being read",
	}
	LockVerifyPathSymlink = Rule{
		ID:          "LOCK_VERIFY_PATH_SYMLINK_DETECTED",
		Severity:    SeverityHigh,
		Description: "lock verify path contains a symlink",
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
	GitHubArchiveSchemeInvalid,
	GitHubArchiveRedirectHostMismatch,
	GitHubArchiveRedirectPortMismatch,
	GitHubArchiveRedirectSchemeInvalid,
	GitHubArchiveRedirectUserinfoDisallowed,
	GitHubArchiveContentTypeInvalid,
	GitHubArchiveContentEncodingInvalid,
	SourceMetadataFileTooLarge,
	SourceMetadataSymlink,
	SourceMetadataSpecialFile,
	SourceMetadataSourceChangedDuringRead,
	SourceMetadataInvalidUTF8,
	LockfileTooLarge,
	LockfileInvalidUTF8,
	LockfileSymlink,
	LockfileSpecialFile,
	LockfileSourceChangedDuringRead,
	InstallTargetSymlink,
	InstallTargetEntrySymlink,
	InstallSourceFileCountExceeded,
	InstallSourceTotalBytesExceeded,
	InstallSourceFileTooLarge,
	InstallSourceSymlink,
	InstallSourceSpecialFile,
	InstallSourceChangedDuringCopy,
	InstallDigestSymlink,
	InstallDigestFileCountExceeded,
	InstallDigestTotalBytesExceeded,
	InstallDigestFileTooLarge,
	InstallDigestSpecialFile,
	InstallDigestSourceChangedDuringHash,
	InstallReportTooLarge,
	InstallReportInvalidUTF8,
	InstallReportSymlink,
	InstallReportSpecialFile,
	InstallReportSourceChangedDuringRead,
	LockVerifyPathSymlink,
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
