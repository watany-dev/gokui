package scan

import "testing"

func TestParseShellNestedSubstringExpansionRejections(t *testing.T) {
	t.Run("rejects input too short after expansion opener", func(t *testing.T) {
		if _, _, ok := parseShellNestedSubstringExpansion("${a", 0); ok {
			t.Fatal("expected rejection for truncated expansion")
		}
	})

	t.Run("rejects unterminated expansion", func(t *testing.T) {
		if _, _, ok := parseShellNestedSubstringExpansion("${VAR:1", 0); ok {
			t.Fatal("expected rejection for unterminated expansion")
		}
	})
}

func TestIsNestedShellSubstringArgListRejections(t *testing.T) {
	t.Run("rejects unterminated nested expansion", func(t *testing.T) {
		if isNestedShellSubstringArgList("${B", 0, 3) {
			t.Fatal("expected rejection for unterminated nested expansion")
		}
	})

	t.Run("rejects non-colon delimiter after first expansion", func(t *testing.T) {
		if isNestedShellSubstringArgList("${B}x", 0, 5) {
			t.Fatal("expected rejection for non-colon delimiter")
		}
	})
}

func TestIsPlainSubstringArg(t *testing.T) {
	t.Run("rejects empty range", func(t *testing.T) {
		if isPlainSubstringArg("abc", 2, 2) {
			t.Fatal("expected rejection for empty range")
		}
	})

	t.Run("rejects brace in range", func(t *testing.T) {
		if isPlainSubstringArg("a{b", 0, 3) {
			t.Fatal("expected rejection for brace in range")
		}
	})

	t.Run("accepts plain range", func(t *testing.T) {
		if !isPlainSubstringArg("1:2", 0, 3) {
			t.Fatal("expected plain range to be accepted")
		}
	})
}

func TestTrimShellSpaceRight(t *testing.T) {
	if got := trimShellSpaceRight("a \t", 0, 3); got != 1 {
		t.Fatalf("trimShellSpaceRight() = %d, want 1", got)
	}
	if got := trimShellSpaceRight("ab", 0, 2); got != 2 {
		t.Fatalf("trimShellSpaceRight() without trailing space = %d, want 2", got)
	}
}

func TestFindShellParamExpansionEndUnterminated(t *testing.T) {
	if got := findShellParamExpansionEnd("${a", 0); got != -1 {
		t.Fatalf("findShellParamExpansionEnd() = %d, want -1", got)
	}
}

func TestNormalizeShellProcCommandSubstitutionsUnterminated(t *testing.T) {
	t.Run("keeps unterminated command substitution", func(t *testing.T) {
		if got := normalizeShellProcCommandSubstitutions("$(foo"); got != "$(foo" {
			t.Fatalf("normalizeShellProcCommandSubstitutions() = %q, want %q", got, "$(foo")
		}
	})

	t.Run("keeps unterminated backtick substitution", func(t *testing.T) {
		if got := normalizeShellProcCommandSubstitutions("`foo"); got != "`foo" {
			t.Fatalf("normalizeShellProcCommandSubstitutions() = %q, want %q", got, "`foo")
		}
	})
}

func TestFindCommandSubstitutionEndSkipsArithmeticOpener(t *testing.T) {
	line := "$(a $((1+2)) )"
	if got := findCommandSubstitutionEnd(line, 0); got < 0 {
		t.Fatalf("findCommandSubstitutionEnd(%q) = %d, want non-negative", line, got)
	}
}

func TestFindBacktickSubstitutionEndUnterminated(t *testing.T) {
	if got := findBacktickSubstitutionEnd("`foo", 0); got != -1 {
		t.Fatalf("findBacktickSubstitutionEnd() = %d, want -1", got)
	}
}
