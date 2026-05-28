package scan

import (
	"strings"
	"testing"
)

func TestNormalizeShellSpecialProcParamsArithmeticExpansion(t *testing.T) {
	line := `command-p source "//proc//$((1+1))//task//$((2+3))//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$((") {
		t.Fatalf("expected arithmetic expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsCommandSubstitution(t *testing.T) {
	line := `command-p source "//proc//$(id -u)//task//$(printf %s $$)//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$(") {
		t.Fatalf("expected command substitution to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsLegacyArithmeticExpansion(t *testing.T) {
	line := `command-p source "//proc//$[1+1]//task//$[2+3]//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$[") {
		t.Fatalf("expected legacy arithmetic expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsTrimExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID##*/}//task//${2%/*}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "##") || strings.Contains(got, "%/") {
		t.Fatalf("expected trim expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsLengthExpansion(t *testing.T) {
	line := `command-p source "//proc//${#PPID}//task//${#2}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "${#") {
		t.Fatalf("expected length expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:1}//task//${2:0:1}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":1") || strings.Contains(got, ":0:1") {
		t.Fatalf("expected substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNegativeSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID: -1}//task//${2: -2:1}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ": -1") || strings.Contains(got, ": -2:1") {
		t.Fatalf("expected negative substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNegativeSubstringLengthExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:1:-1}//task//${2:2:-1}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":1:-1") || strings.Contains(got, ":2:-1") {
		t.Fatalf("expected negative substring length expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsSpacedPositiveSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID: 1}//task//${2: 2:1}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ": 1") || strings.Contains(got, ": 2:1") {
		t.Fatalf("expected spaced positive substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsArithmeticSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:$((1+1))}//task//${2:$((2+3)):$((1+1))}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$((") {
		t.Fatalf("expected arithmetic substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsVariableSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:off}//task//${2:off:len}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":off") || strings.Contains(got, ":off:len") {
		t.Fatalf("expected variable substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedBraceSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF}}//task//${2:${OFF}:${LEN}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${OFF}") || strings.Contains(got, ":${OFF}:${LEN}") {
		t.Fatalf("expected nested-brace substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedPositionalBraceSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${1}}//task//${2:${3}:${4}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${1}") || strings.Contains(got, ":${3}:${4}") {
		t.Fatalf("expected nested positional-brace substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedDefaultBraceSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF:-1}}//task//${2:${TOFF:-1}:${TLEN:-1}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${OFF:-1}") || strings.Contains(got, ":${TOFF:-1}:${TLEN:-1}") {
		t.Fatalf("expected nested default-brace substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedFallbackBraceSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF:-${ALT}}}//task//${2:${TOFF:-${TALT}}:${TLEN:-${LLEN}}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${OFF:-${ALT}}") || strings.Contains(got, ":${TOFF:-${TALT}}:${TLEN:-${LLEN}}") {
		t.Fatalf("expected nested fallback-brace substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedMixedSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF}:1}//task//${2:${TOFF}:${TLEN:-1}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${OFF}:1") || strings.Contains(got, ":${TOFF}:${TLEN:-1}") {
		t.Fatalf("expected nested mixed substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsPlainFirstNestedSecondSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:1:${LEN:-1}}//task//${2:2:${TLEN:-${TALT}}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":1:${LEN:-1}") || strings.Contains(got, ":2:${TLEN:-${TALT}}") {
		t.Fatalf("expected plain-first nested-second substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsSpacedPlainFirstNestedSecondSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:1: ${LEN:-1}}//task//${2: 2 : ${TLEN:-${TALT}}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":1: ${LEN:-1}") || strings.Contains(got, ": 2 : ${TLEN:-${TALT}}") {
		t.Fatalf("expected spaced plain-first nested-second substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsTabbedPlainFirstNestedSecondSubstringExpansion(t *testing.T) {
	line := "command-p source \"//proc//${PPID:\t1:\t${LEN:-1}}//task//${2:\t2\t:\t${TLEN:-${TALT}}}//fd//0\""
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":\t1:\t${LEN:-1}") || strings.Contains(got, ":\t2\t:\t${TLEN:-${TALT}}") {
		t.Fatalf("expected tabbed plain-first nested-second substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsSpacedDelimiterNestedFirstSubstringExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF} : ${LEN}}//task//${2:${TOFF} : ${TLEN:-${TALT}}}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, ":${OFF} : ${LEN}") || strings.Contains(got, ":${TOFF} : ${TLEN:-${TALT}}") {
		t.Fatalf("expected spaced-delimiter nested-first substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellNestedSubstringExpansionsDeepNestedFallback(t *testing.T) {
	line := `command-p source "//proc//${PPID:${OFF:-${ALT:-${DEF}}}}//task//${2:${TOFF:-${TALT:-${TD}}}:${TLEN:-${LLEN:-${LD}}}}//fd//0"`
	got := normalizeShellNestedSubstringExpansions(line)
	if strings.Contains(got, ":${OFF:-${ALT:-${DEF}}}") || strings.Contains(got, ":${TOFF:-${TALT:-${TD}}}:${TLEN:-${LLEN:-${LD}}}") {
		t.Fatalf("expected deep nested fallback-brace substring expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestParseShellNestedSubstringExpansionRejectsInvalidHeads(t *testing.T) {
	line := `${12345678901:${OFF}}`
	if _, _, ok := parseShellNestedSubstringExpansion(line, 0); ok {
		t.Fatalf("expected positional head with >10 digits to be rejected")
	}
	line = `${-BAD:${OFF}}`
	if _, _, ok := parseShellNestedSubstringExpansion(line, 0); ok {
		t.Fatalf("expected non-name/non-positional head to be rejected")
	}
}

func TestParseShellNestedSubstringExpansionRejectsNonNestedArgs(t *testing.T) {
	line := `${PPID:1}`
	if _, _, ok := parseShellNestedSubstringExpansion(line, 0); ok {
		t.Fatalf("expected non-nested substring args to be rejected")
	}
}

func TestFindShellParamExpansionEndRejectsUnbalancedClosing(t *testing.T) {
	if got := findShellParamExpansionEnd("}", 0); got != -1 {
		t.Fatalf("expected unbalanced closing brace to return -1, got %d", got)
	}
}

func TestNormalizeShellSpecialProcParamsDoesNotRewriteDefaultExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID:-1}//task//${2:-1}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if got != line {
		t.Fatalf("expected default expansion to remain unchanged, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsCaseModifierExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID^^}//task//${2,}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "${PPID^^}") || strings.Contains(got, "${2,}") {
		t.Fatalf("expected case modifier expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsCaseModifierPatternExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID^^[[:digit:]]}//task//${2,?}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "${PPID^^[[:digit:]]}") || strings.Contains(got, "${2,?}") {
		t.Fatalf("expected case modifier pattern expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsTransformExpansion(t *testing.T) {
	line := `command-p source "//proc//${PPID@Q}//task//${2@a}//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "${PPID@Q}") || strings.Contains(got, "${2@a}") {
		t.Fatalf("expected transform expansion to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//${PPID}//task//${2}//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsNestedCommandSubstitution(t *testing.T) {
	line := `command-p source "//proc//$(echo $(id -u))//task//$(printf %s $(id -u))//fd//0"`
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$(") {
		t.Fatalf("expected nested command substitution to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsBacktickSubstitution(t *testing.T) {
	line := "command-p source \"//proc//`id -u`//task//`printf %s $$`//fd//0\""
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "`") {
		t.Fatalf("expected backtick substitution to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsEscapedBacktickSubstitution(t *testing.T) {
	line := "command-p source \"//proc//`echo \\`id -u\\``//task//`printf %s \\`id -u\\``//fd//0\""
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "`") {
		t.Fatalf("expected escaped backtick substitution to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}

func TestNormalizeShellSpecialProcParamsAnsiCQuote(t *testing.T) {
	line := "command-p source \"//proc//$'123'//task//$'456'//fd//0\""
	got := normalizeShellSpecialProcParams(line)
	if strings.Contains(got, "$'") {
		t.Fatalf("expected ANSI-C quote to be normalized, got %q", got)
	}
	if !strings.Contains(got, `//proc//$$//task//$$//fd//0`) {
		t.Fatalf("expected normalized proc path, got %q", got)
	}
}
