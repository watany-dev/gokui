package scan

import "strings"

func normalizeShellAssignDefaultExpansions(line string) string {
	if !strings.Contains(line, "${") {
		return line
	}
	out := shellEmptyColonDashNamedPattern.ReplaceAllString(line, `${$1}`)
	out = shellEmptyColonDashPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyDashNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyDashPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyAssignDefaultNamed.ReplaceAllString(out, `${$1}`)
	out = shellEmptyAssignDefaultPos.ReplaceAllString(out, `${$1}`)
	out = shellEmptyAssignNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyAssignPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyErrorDefaultNamed.ReplaceAllString(out, `${$1}`)
	out = shellEmptyErrorDefaultPos.ReplaceAllString(out, `${$1}`)
	out = shellEmptyErrorNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptyErrorPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptySetSubDefaultNamed.ReplaceAllString(out, `${$1}`)
	out = shellEmptySetSubDefaultPos.ReplaceAllString(out, `${$1}`)
	out = shellEmptySetSubNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellEmptySetSubPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellAssignDefaultNamedPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellAssignDefaultPosPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellAssignNamedPattern.ReplaceAllString(out, `${$1-$2}`)
	out = shellAssignPosPattern.ReplaceAllString(out, `${$1-$2}`)
	out = shellSetSubDefaultNamedPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellSetSubDefaultPosPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellSetSubNamedPattern.ReplaceAllString(out, `${$1-$2}`)
	out = shellSetSubPosPattern.ReplaceAllString(out, `${$1-$2}`)
	out = shellErrorDefaultNamedPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellErrorDefaultPosPattern.ReplaceAllString(out, `${$1:-$2}`)
	out = shellErrorNamedPattern.ReplaceAllString(out, `${$1-$2}`)
	out = shellErrorPosPattern.ReplaceAllString(out, `${$1-$2}`)
	return out
}

func normalizeShellSpecialProcParams(line string) string {
	if !strings.Contains(line, "/proc/") && !strings.Contains(line, "//proc//") {
		return line
	}
	out := normalizeShellNestedSubstringExpansions(line)
	out = shellIndirectNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellIndirectPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellTrimPrefixNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellTrimPrefixPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellTrimPrefixShortNamed.ReplaceAllString(out, `${$1}`)
	out = shellTrimPrefixShortPos.ReplaceAllString(out, `${$1}`)
	out = shellTrimSuffixNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellTrimSuffixPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellTrimSuffixShortNamed.ReplaceAllString(out, `${$1}`)
	out = shellTrimSuffixShortPos.ReplaceAllString(out, `${$1}`)
	out = shellSubstringNamedNestedPattern.ReplaceAllString(out, `${$1}`)
	out = shellSubstringPosNestedPattern.ReplaceAllString(out, `${$1}`)
	out = shellSubstringNamedVarPattern.ReplaceAllString(out, `${$1}`)
	out = shellSubstringPosVarPattern.ReplaceAllString(out, `${$1}`)
	out = shellSubstringNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellSubstringPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellTransformNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellTransformPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperNamedWithPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperPosWithPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerNamedWithPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerPosWithPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperFirstNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperFirstPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerFirstNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerFirstPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerPosPattern.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperFirstNamed.ReplaceAllString(out, `${$1}`)
	out = shellCaseUpperFirstPos.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerFirstNamed.ReplaceAllString(out, `${$1}`)
	out = shellCaseLowerFirstPos.ReplaceAllString(out, `${$1}`)
	out = shellLengthNamedPattern.ReplaceAllString(out, `${$1}`)
	out = shellLengthPosPattern.ReplaceAllString(out, `${$1}`)
	out = normalizeShellProcCommandSubstitutions(out)
	out = shellArithmeticExpansionPattern.ReplaceAllString(out, "$$$$")
	out = shellLegacyArithmeticPattern.ReplaceAllString(out, "$$$$")
	out = shellAnsiCQuotePattern.ReplaceAllString(out, "$$$$")
	out = strings.ReplaceAll(out, "$!", "$$")
	out = strings.ReplaceAll(out, "$?", "$$")
	out = strings.ReplaceAll(out, "$#", "$$")
	out = strings.ReplaceAll(out, "$*", "$$")
	out = strings.ReplaceAll(out, "$@", "$$")
	out = strings.ReplaceAll(out, "$-", "$$")
	out = strings.ReplaceAll(out, "${!}", "$$")
	out = strings.ReplaceAll(out, "${?}", "$$")
	out = strings.ReplaceAll(out, "${#}", "$$")
	out = strings.ReplaceAll(out, "${*}", "$$")
	out = strings.ReplaceAll(out, "${@}", "$$")
	out = strings.ReplaceAll(out, "${-}", "$$")
	out = shellProcDollarSubstringNamed.ReplaceAllString(out, `${$1}`)
	out = shellProcDollarSubstringPos.ReplaceAllString(out, `${$1}`)
	return out
}

func normalizeShellNestedSubstringExpansions(line string) string {
	if !strings.Contains(line, "${") {
		return line
	}

	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); {
		if i+1 >= len(line) || line[i] != '$' || line[i+1] != '{' {
			b.WriteByte(line[i])
			i++
			continue
		}
		end, head, ok := parseShellNestedSubstringExpansion(line, i)
		if !ok {
			b.WriteByte(line[i])
			i++
			continue
		}
		b.WriteString("${")
		b.WriteString(head)
		b.WriteByte('}')
		i = end + 1
	}
	return b.String()
}

func parseShellNestedSubstringExpansion(line string, start int) (int, string, bool) {
	if start+3 >= len(line) {
		return -1, "", false
	}

	j := start + 2
	if isShellNameStart(line[j]) {
		j++
		for j < len(line) && isShellNameChar(line[j]) {
			j++
		}
	} else if isDigitByte(line[j]) {
		k := 0
		for j < len(line) && isDigitByte(line[j]) && k < 10 {
			j++
			k++
		}
		if k == 0 || (j < len(line) && isDigitByte(line[j])) {
			return -1, "", false
		}
	} else {
		return -1, "", false
	}

	if j >= len(line) || line[j] != ':' {
		return -1, "", false
	}

	end := findShellParamExpansionEnd(line, start)
	if end < 0 {
		return -1, "", false
	}
	argsStart := j + 1
	if !isNestedShellSubstringArgList(line, argsStart, end) && !isPlainFirstNestedSecondSubstringArgList(line, argsStart, end) {
		return -1, "", false
	}
	return end, line[start+2 : j], true
}

func isNestedShellSubstringArgList(line string, start, outerEnd int) bool {
	start = skipShellSpace(line, start, outerEnd)
	outerEnd = trimShellSpaceRight(line, start, outerEnd)
	if start+1 >= outerEnd || line[start] != '$' || line[start+1] != '{' {
		return false
	}

	firstEnd := findShellParamExpansionEnd(line, start)
	if firstEnd < 0 || firstEnd >= outerEnd {
		return false
	}
	if firstEnd == outerEnd-1 {
		return true
	}
	firstDelim := skipShellSpace(line, firstEnd+1, outerEnd)
	if firstDelim >= outerEnd || line[firstDelim] != ':' {
		return false
	}

	secondStart := firstDelim + 1
	secondStart = skipShellSpace(line, secondStart, outerEnd)
	outerEnd = trimShellSpaceRight(line, secondStart, outerEnd)
	if secondStart+1 < outerEnd && line[secondStart] == '$' && line[secondStart+1] == '{' {
		secondEnd := findShellParamExpansionEnd(line, secondStart)
		return secondEnd == outerEnd-1
	}
	return isPlainSubstringArg(line, secondStart, outerEnd)
}

func isPlainSubstringArg(line string, start, outerEnd int) bool {
	if start >= outerEnd {
		return false
	}
	for i := start; i < outerEnd; i++ {
		if line[i] == '{' || line[i] == '}' || line[i] == '\n' {
			return false
		}
	}
	return true
}

func isPlainFirstNestedSecondSubstringArgList(line string, start, outerEnd int) bool {
	start = skipShellSpace(line, start, outerEnd)
	outerEnd = trimShellSpaceRight(line, start, outerEnd)
	sep := -1
	for i := start; i < outerEnd; i++ {
		if line[i] == ':' {
			sep = i
			break
		}
		if line[i] == '{' || line[i] == '}' || line[i] == '\n' {
			return false
		}
	}
	if sep < 0 || sep <= start || sep+1 >= outerEnd {
		return false
	}
	if !isPlainSubstringArg(line, start, sep) {
		return false
	}
	secondStart := skipShellSpace(line, sep+1, outerEnd)
	outerEnd = trimShellSpaceRight(line, secondStart, outerEnd)
	if secondStart+1 < outerEnd && line[secondStart] == '$' && line[secondStart+1] == '{' {
		secondEnd := findShellParamExpansionEnd(line, secondStart)
		return secondEnd == outerEnd-1
	}
	return false
}

func skipShellSpace(line string, start, outerEnd int) int {
	i := start
	for i < outerEnd && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return i
}

func trimShellSpaceRight(line string, start, outerEnd int) int {
	i := outerEnd
	for i > start && (line[i-1] == ' ' || line[i-1] == '\t') {
		i--
	}
	return i
}

func findShellParamExpansionEnd(line string, start int) int {
	depth := 0
	for i := start; i < len(line); i++ {
		if i+1 < len(line) && line[i] == '$' && line[i+1] == '{' {
			depth++
			i++
			continue
		}
		if line[i] != '}' {
			continue
		}
		depth--
		if depth == 0 {
			return i
		}
		if depth < 0 {
			return -1
		}
	}
	return -1
}

func isShellNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isShellNameChar(c byte) bool {
	return isShellNameStart(c) || isDigitByte(c)
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

func normalizeShellProcCommandSubstitutions(line string) string {
	if !strings.Contains(line, "$(") && !strings.Contains(line, "`") {
		return line
	}

	var b strings.Builder
	b.Grow(len(line))
	for i := 0; i < len(line); {
		if i+1 < len(line) && line[i] == '$' && line[i+1] == '(' {
			// Keep arithmetic expansion for dedicated normalization.
			if i+2 < len(line) && line[i+2] == '(' {
				b.WriteString("$(")
				i += 2
				continue
			}
			end := findCommandSubstitutionEnd(line, i)
			if end < 0 {
				b.WriteString(line[i:])
				break
			}
			b.WriteString("$$")
			i = end + 1
			continue
		}
		if line[i] == '`' {
			end := findBacktickSubstitutionEnd(line, i)
			if end < 0 {
				b.WriteByte(line[i])
				i++
				continue
			}
			b.WriteString("$$")
			i = end + 1
			continue
		}
		b.WriteByte(line[i])
		i++
	}
	return b.String()
}

func findCommandSubstitutionEnd(line string, start int) int {
	depth := 1
	for i := start + 2; i < len(line); i++ {
		if i+1 < len(line) && line[i] == '$' && line[i+1] == '(' {
			// Skip arithmetic expansion opener "$(("; handled by separate normalization.
			if i+2 < len(line) && line[i+2] == '(' {
				i++
				continue
			}
			depth++
			i++
			continue
		}
		if line[i] == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func findBacktickSubstitutionEnd(line string, start int) int {
	escaped := false
	for i := start + 1; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if line[i] == '\\' {
			escaped = true
			continue
		}
		if line[i] == '`' {
			return i
		}
	}
	return -1
}
