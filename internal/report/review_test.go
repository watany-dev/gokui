package report

import (
	"strings"
	"testing"
)

func TestNeutralizeReviewText(t *testing.T) {
	got := NeutralizeReviewText("line1\nline2 \u202E hidden")
	if !strings.Contains(got, `\n`) {
		t.Fatalf("expected escaped newline, got %q", got)
	}
	if strings.ContainsRune(got, '\u202e') {
		t.Fatalf("expected bidi rune to be escaped, got %q", got)
	}
	if !strings.Contains(got, `\u202e`) {
		t.Fatalf("expected ASCII unicode escape, got %q", got)
	}
}

func TestNeutralizeReviewTextInvalidUTF8(t *testing.T) {
	got := NeutralizeReviewText(string([]byte{'o', 'k', 0xff}))
	if strings.ContainsRune(got, '\ufffd') {
		t.Fatalf("replacement rune should be escaped, got %q", got)
	}
	if !strings.Contains(got, `\ufffd`) {
		t.Fatalf("expected escaped replacement rune, got %q", got)
	}
}
