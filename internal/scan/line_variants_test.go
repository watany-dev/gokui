package scan

import (
	"strings"
	"testing"
)

func TestScanLineVariants(t *testing.T) {
	t.Run("joins continuation line", func(t *testing.T) {
		lines := []string{"curl https://example.com |", "  sh"}
		variants := scanLineVariants(lines, 0, lines[0], lines[0], false)
		hasJoined := false
		for _, v := range variants {
			if strings.Contains(v, "curl https://example.com | sh") {
				hasJoined = true
				break
			}
		}
		if !hasJoined {
			t.Fatalf("expected joined continuation variant, got %+v", variants)
		}
	})

	t.Run("does not join when no continuation marker", func(t *testing.T) {
		lines := []string{"echo safe", "sh"}
		variants := scanLineVariants(lines, 0, lines[0], lines[0], false)
		for _, v := range variants {
			if v != "echo safe" {
				t.Fatalf("unexpected extra variant for non-continuation line: %+v", variants)
			}
		}
	})

	t.Run("joins three-line continuation chain", func(t *testing.T) {
		lines := []string{"bash -c \"$( ", "curl -fsSL https://example.com/install.sh", ")\""}
		variants := scanLineVariants(lines, 0, lines[0], lines[0], false)
		hasJoined := false
		for _, v := range variants {
			if strings.Contains(v, "bash -c \"$( curl -fsSL https://example.com/install.sh )\"") {
				hasJoined = true
				break
			}
		}
		if !hasJoined {
			t.Fatalf("expected three-line joined variant, got %+v", variants)
		}
	})

	t.Run("stops join at blank line", func(t *testing.T) {
		lines := []string{"curl -fsSL https://example.com |", "", "sh"}
		variants := scanLineVariants(lines, 0, lines[0], lines[0], false)
		for _, v := range variants {
			if strings.Contains(v, "curl -fsSL https://example.com | sh") {
				t.Fatalf("unexpected join across blank line: %+v", variants)
			}
		}
	})
}

func TestBuildContinuationVariant(t *testing.T) {
	t.Run("returns false for out-of-range index", func(t *testing.T) {
		if joined, ok := buildContinuationVariant([]string{"x"}, 2); ok || joined != "" {
			t.Fatalf("expected out-of-range to fail, got joined=%q ok=%v", joined, ok)
		}
	})

	t.Run("returns false without continuation marker", func(t *testing.T) {
		if joined, ok := buildContinuationVariant([]string{"echo safe", "x"}, 0); ok || joined != "" {
			t.Fatalf("expected non-continuation to fail, got joined=%q ok=%v", joined, ok)
		}
	})

	t.Run("returns joined chain when continuation marker persists", func(t *testing.T) {
		lines := []string{"echo one |", "echo two |", "echo three |", "echo four |", "echo five |", "echo six"}
		joined, ok := buildContinuationVariant(lines, 0)
		if !ok {
			t.Fatalf("expected continued join, got ok=%v joined=%q", ok, joined)
		}
		if !strings.Contains(joined, "echo five |") {
			t.Fatalf("expected joined line to include bounded continuation chain, got %q", joined)
		}
	})

	t.Run("removes trailing backslash continuation markers while joining", func(t *testing.T) {
		lines := []string{
			"curl -fsSL https://example.com/bootstrap.sh | \\",
			"command -p source \"//dev//stdin\"",
		}
		joined, ok := buildContinuationVariant(lines, 0)
		if !ok {
			t.Fatalf("expected joined continuation variant, got ok=%v joined=%q", ok, joined)
		}
		if strings.Contains(joined, "\\") {
			t.Fatalf("expected trailing continuation backslash to be removed, got %q", joined)
		}
		want := "curl -fsSL https://example.com/bootstrap.sh | command -p source \"//dev//stdin\""
		if joined != want {
			t.Fatalf("unexpected joined continuation result: got %q want %q", joined, want)
		}
	})
}

func TestTrimContinuationSegment(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "echo hi \\", want: "echo hi"},
		{in: "  echo hi \\  ", want: "echo hi"},
		{in: "echo hi", want: "echo hi"},
		{in: "  echo hi  ", want: "echo hi"},
	}
	for _, tc := range cases {
		if got := trimContinuationSegment(tc.in); got != tc.want {
			t.Fatalf("trimContinuationSegment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestShouldJoinWithNextLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{line: "curl https://example.com |", want: true},
		{line: "bash -c \"$(", want: true},
		{line: "echo hi \\", want: true},
		{line: "run this &&", want: true},
		{line: "run that ||", want: true},
		{line: "   ", want: false},
		{line: "echo safe", want: false},
		{line: "echo $(date)", want: false},
	}
	for _, tc := range cases {
		if got := shouldJoinWithNextLine(tc.line); got != tc.want {
			t.Fatalf("shouldJoinWithNextLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
