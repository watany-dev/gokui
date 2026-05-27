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
		{MixedScriptFilename, "MIXED_SCRIPT_FILENAME", SeverityMedium},
		{ConfusableFilename, "CONFUSABLE_FILENAME", SeverityHigh},
		{LinkSpoofingURLMismatch, "LINK_SPOOFING_URL_MISMATCH", SeverityHigh},
		{RawIPURL, "RAW_IP_URL", SeverityHigh},
		{URLShortener, "URL_SHORTENER", SeverityMedium},
		{PasteSiteURL, "PASTE_SITE_URL", SeverityMedium},
		{ReleaseAssetURL, "RELEASE_ASSET_URL", SeverityMedium},
		{RemoteImageURL, "REMOTE_IMAGE_URL", SeverityMedium},
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
