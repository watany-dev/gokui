package format

import "testing"

func TestSupportsCommand(t *testing.T) {
	for _, f := range []Format{Human, JSON, SARIF, Compact} {
		if !SupportsCommand(f.String()) {
			t.Fatalf("SupportsCommand(%q) = false, want true", f)
		}
	}
	if SupportsCommand(ReviewJSON.String()) {
		t.Fatal("SupportsCommand(review-json) = true, want false")
	}
	if SupportsCommand("xml") {
		t.Fatal("SupportsCommand(xml) = true, want false")
	}
}

func TestSupportsReviewCommand(t *testing.T) {
	for _, f := range []Format{Human, JSON, SARIF, Compact, ReviewJSON} {
		if !SupportsReviewCommand(f.String()) {
			t.Fatalf("SupportsReviewCommand(%q) = false, want true", f)
		}
	}
	if SupportsReviewCommand("xml") {
		t.Fatal("SupportsReviewCommand(xml) = true, want false")
	}
}

func TestIsStructured(t *testing.T) {
	for _, f := range []Format{JSON, SARIF, ReviewJSON} {
		if !IsStructured(f.String()) {
			t.Fatalf("IsStructured(%q) = false, want true", f)
		}
	}
	for _, f := range []Format{Human, Compact} {
		if IsStructured(f.String()) {
			t.Fatalf("IsStructured(%q) = true, want false", f)
		}
	}
}
