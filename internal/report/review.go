package report

import (
	"strconv"
	"strings"
)

// NeutralizeReviewText escapes untrusted text before it is emitted into
// review-oriented JSON intended for display in code review systems.
func NeutralizeReviewText(text string) string {
	valid := strings.ToValidUTF8(text, "\uFFFD")
	quoted := strconv.QuoteToASCII(valid)
	return quoted[1 : len(quoted)-1]
}
