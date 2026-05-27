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
