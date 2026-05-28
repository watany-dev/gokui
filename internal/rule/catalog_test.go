package rule

import "testing"

func TestCatalogIncludesScanRules(t *testing.T) {
	cases := []struct {
		rule Rule
		id   string
		sev  Severity
	}{
		{ANSIOSCEscapeInText, "ANSI_OSC_ESCAPE_IN_TEXT", SeverityCritical},
		{UnicodeTagInInstructions, "UNICODE_TAG_IN_INSTRUCTIONS", SeverityCritical},
		{BidiControlInText, "BIDI_CONTROL_IN_TEXT", SeverityCritical},
		{VariationSelectorInText, "VARIATION_SELECTOR_IN_TEXT", SeverityCritical},
		{ZeroWidthCharInText, "ZERO_WIDTH_CHAR_IN_TEXT", SeverityCritical},
		{ControlCharInText, "CONTROL_CHAR_IN_TEXT", SeverityCritical},
		{NFKCChangesText, "NFKC_CHANGES_TEXT", SeverityMedium},
		{UnknownFileType, "UNKNOWN_FILE_TYPE", SeverityMedium},
		{LargeTextFile, "LARGE_TEXT_FILE", SeverityMedium},
		{NonUTF8Text, "NON_UTF8_TEXT", SeverityHigh},
		{CurlPipeShell, "CURL_PIPE_SHELL", SeverityCritical},
		{Base64PipeExec, "BASE64_PIPE_EXEC", SeverityCritical},
		{HexPipeExec, "HEX_PIPE_EXEC", SeverityCritical},
		{EncodedCommandExec, "ENCODED_COMMAND_EXEC", SeverityCritical},
		{ChmodExecChain, "CHMOD_EXEC_CHAIN", SeverityCritical},
		{WritesHomeConfig, "WRITES_HOME_CONFIG", SeverityHigh},
		{SecretExfil, "SECRET_EXFIL", SeverityCritical},
		{AllowedToolsBashWildcard, "ALLOWED_TOOLS_BASH_WILDCARD", SeverityHigh},
		{UnpinnedRuntimeTool, "UNPINNED_RUNTIME_TOOL", SeverityHigh},
		{FakePrereqExecution, "FAKE_PREREQ_EXECUTION", SeverityCritical},
		{ExternalBinaryDownload, "EXTERNAL_BINARY_DOWNLOAD", SeverityHigh},
		{PromptOverrideLanguage, "PROMPT_OVERRIDE_LANGUAGE", SeverityHigh},
		{PasswordProtectedArchive, "PASSWORD_PROTECTED_ARCHIVE", SeverityHigh},
		{RawHTMLMarkup, "RAW_HTML_MARKUP", SeverityMedium},
		{MixedScriptFilename, "MIXED_SCRIPT_FILENAME", SeverityMedium},
		{ConfusableFilename, "CONFUSABLE_FILENAME", SeverityHigh},
		{LinkSpoofingURLMismatch, "LINK_SPOOFING_URL_MISMATCH", SeverityHigh},
		{RawIPURL, "RAW_IP_URL", SeverityHigh},
		{URLShortener, "URL_SHORTENER", SeverityMedium},
		{PasteSiteURL, "PASTE_SITE_URL", SeverityMedium},
		{ReleaseAssetURL, "RELEASE_ASSET_URL", SeverityMedium},
		{RemoteImageURL, "REMOTE_IMAGE_URL", SeverityMedium},
		{SymlinkInScanSource, "SYMLINK_IN_SCAN_SOURCE", SeverityHigh},
		{ScanFileCountExceeded, "SCAN_FILE_COUNT_EXCEEDED", SeverityHigh},
		{SpecialFileInScanSource, "SPECIAL_FILE_IN_SCAN_SOURCE", SeverityHigh},
		{ScanSourceChangedDuringRead, "SCAN_SOURCE_CHANGED_DURING_READ", SeverityHigh},
		{FetchOutputSymlink, "FETCH_OUTPUT_SYMLINK_DETECTED", SeverityHigh},
		{FetchOutputEntrySymlink, "FETCH_OUTPUT_ENTRY_SYMLINK_DETECTED", SeverityHigh},
		{GitHubArchiveSchemeInvalid, "GITHUB_ARCHIVE_SCHEME_INVALID", SeverityHigh},
		{GitHubArchiveRedirectHostMismatch, "GITHUB_ARCHIVE_REDIRECT_HOST_MISMATCH", SeverityHigh},
		{GitHubArchiveRedirectPortMismatch, "GITHUB_ARCHIVE_REDIRECT_PORT_MISMATCH", SeverityHigh},
		{GitHubArchiveRedirectSchemeInvalid, "GITHUB_ARCHIVE_REDIRECT_SCHEME_INVALID", SeverityHigh},
		{GitHubArchiveRedirectUserinfoDisallowed, "GITHUB_ARCHIVE_REDIRECT_USERINFO_DISALLOWED", SeverityHigh},
		{GitHubArchiveContentTypeInvalid, "GITHUB_ARCHIVE_CONTENT_TYPE_INVALID", SeverityHigh},
		{GitHubArchiveContentEncodingInvalid, "GITHUB_ARCHIVE_CONTENT_ENCODING_INVALID", SeverityHigh},
		{SourceMetadataFileTooLarge, "SOURCE_METADATA_FILE_TOO_LARGE", SeverityHigh},
		{SourceMetadataSymlink, "SOURCE_METADATA_SYMLINK_DETECTED", SeverityHigh},
		{SourceMetadataSpecialFile, "SOURCE_METADATA_SPECIAL_FILE", SeverityHigh},
		{SourceMetadataSourceChangedDuringRead, "SOURCE_METADATA_SOURCE_CHANGED_DURING_READ", SeverityHigh},
		{SourceMetadataInvalidUTF8, "SOURCE_METADATA_INVALID_UTF8", SeverityHigh},
		{LockfileTooLarge, "LOCKFILE_TOO_LARGE", SeverityHigh},
		{LockfileInvalidUTF8, "LOCKFILE_INVALID_UTF8", SeverityHigh},
		{LockfileSymlink, "LOCKFILE_SYMLINK_DETECTED", SeverityHigh},
		{LockfileSpecialFile, "LOCKFILE_SPECIAL_FILE", SeverityHigh},
		{LockfileSourceChangedDuringRead, "LOCKFILE_SOURCE_CHANGED_DURING_READ", SeverityHigh},
		{InstallTargetSymlink, "INSTALL_TARGET_SYMLINK_DETECTED", SeverityHigh},
		{InstallTargetEntrySymlink, "INSTALL_TARGET_ENTRY_SYMLINK_DETECTED", SeverityHigh},
		{InstallSourceFileCountExceeded, "INSTALL_SOURCE_FILE_COUNT_EXCEEDED", SeverityHigh},
		{InstallSourceTotalBytesExceeded, "INSTALL_SOURCE_TOTAL_BYTES_EXCEEDED", SeverityHigh},
		{InstallSourceFileTooLarge, "INSTALL_SOURCE_FILE_TOO_LARGE", SeverityHigh},
		{InstallSourceSymlink, "INSTALL_SOURCE_SYMLINK_DETECTED", SeverityHigh},
		{InstallSourceSpecialFile, "INSTALL_SOURCE_SPECIAL_FILE", SeverityHigh},
		{InstallSourceChangedDuringCopy, "INSTALL_SOURCE_CHANGED_DURING_COPY", SeverityHigh},
		{InstallDigestSymlink, "INSTALL_DIGEST_SYMLINK_DETECTED", SeverityHigh},
		{InstallDigestFileCountExceeded, "INSTALL_DIGEST_FILE_COUNT_EXCEEDED", SeverityHigh},
		{InstallDigestTotalBytesExceeded, "INSTALL_DIGEST_TOTAL_BYTES_EXCEEDED", SeverityHigh},
		{InstallDigestFileTooLarge, "INSTALL_DIGEST_FILE_TOO_LARGE", SeverityHigh},
		{InstallDigestSpecialFile, "INSTALL_DIGEST_SPECIAL_FILE", SeverityHigh},
		{InstallDigestSourceChangedDuringHash, "INSTALL_DIGEST_SOURCE_CHANGED_DURING_HASH", SeverityHigh},
		{InstallReportTooLarge, "INSTALL_REPORT_TOO_LARGE", SeverityHigh},
		{InstallReportInvalidUTF8, "INSTALL_REPORT_INVALID_UTF8", SeverityHigh},
		{InstallReportSymlink, "INSTALL_REPORT_SYMLINK_DETECTED", SeverityHigh},
		{InstallReportSpecialFile, "INSTALL_REPORT_SPECIAL_FILE", SeverityHigh},
		{InstallReportSourceChangedDuringRead, "INSTALL_REPORT_SOURCE_CHANGED_DURING_READ", SeverityHigh},
		{LockVerifyPathSymlink, "LOCK_VERIFY_PATH_SYMLINK_DETECTED", SeverityHigh},
	}

	for _, tc := range cases {
		if tc.rule.ID != tc.id {
			t.Fatalf("rule ID = %q, want %q", tc.rule.ID, tc.id)
		}
		if tc.rule.Severity != tc.sev {
			t.Fatalf("%s severity = %q, want %q", tc.id, tc.rule.Severity, tc.sev)
		}
		if tc.rule.Description == "" {
			t.Fatalf("%s description must not be empty", tc.id)
		}
		got, ok := Lookup(tc.id)
		if !ok {
			t.Fatalf("Lookup(%q) did not find rule", tc.id)
		}
		if got != tc.rule {
			t.Fatalf("Lookup(%q) = %+v, want %+v", tc.id, got, tc.rule)
		}
	}
}

func TestCatalogRuleIDsAreUnique(t *testing.T) {
	seen := map[string]struct{}{}
	for _, r := range catalog {
		if r.ID == "" {
			t.Fatal("catalog rule ID must not be empty")
		}
		if _, ok := seen[r.ID]; ok {
			t.Fatalf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = struct{}{}
	}
}
