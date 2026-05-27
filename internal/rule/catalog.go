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
	MixedScriptFilename,
	ConfusableFilename,
	LinkSpoofingURLMismatch,
	RawIPURL,
	URLShortener,
	PasteSiteURL,
	ReleaseAssetURL,
	RemoteImageURL,
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
