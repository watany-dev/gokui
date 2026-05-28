package format

// Format is a supported CLI output format.
type Format string

const (
	Human      Format = "human"
	JSON       Format = "json"
	SARIF      Format = "sarif"
	Compact    Format = "compact"
	ReviewJSON Format = "review-json"
)

func (f Format) String() string {
	return string(f)
}

func SupportsCommand(format string) bool {
	switch Format(format) {
	case Human, JSON, SARIF, Compact:
		return true
	default:
		return false
	}
}

func SupportsReviewCommand(format string) bool {
	return SupportsCommand(format) || Format(format) == ReviewJSON
}
