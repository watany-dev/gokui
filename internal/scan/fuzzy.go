package scan

func hasPromptOverrideApproximatePhrase(line string) bool {
	tokens := tokenizeWords(line)
	if len(tokens) == 0 {
		return false
	}
	for _, phrase := range promptOverridePhrases {
		if len(tokens) < len(phrase) {
			continue
		}
		for i := 0; i <= len(tokens)-len(phrase); i++ {
			if matchesApproximatePhrase(tokens[i:i+len(phrase)], phrase) {
				return true
			}
		}
	}
	return false
}

func matchesApproximatePhrase(window []string, phrase []string) bool {
	if len(window) != len(phrase) {
		return false
	}
	for i := range phrase {
		if !isApproxWordMatch(window[i], phrase[i]) {
			return false
		}
	}
	return true
}

func isApproxWordMatch(in string, want string) bool {
	if in == want {
		return true
	}
	if len(in) < 3 || len(want) < 3 {
		return false
	}
	if isTypoglycemiaVariant(in, want) {
		return true
	}
	return boundedLevenshteinDistance(in, want, 1) <= 1
}

func isTypoglycemiaVariant(in string, want string) bool {
	inRunes := []rune(in)
	wantRunes := []rune(want)
	if len(inRunes) != len(wantRunes) || len(inRunes) < 4 {
		return false
	}
	if inRunes[0] != wantRunes[0] || inRunes[len(inRunes)-1] != wantRunes[len(wantRunes)-1] {
		return false
	}
	inMiddle := make(map[rune]int, len(inRunes))
	wantMiddle := make(map[rune]int, len(wantRunes))
	for i := 1; i < len(inRunes)-1; i++ {
		inMiddle[inRunes[i]]++
		wantMiddle[wantRunes[i]]++
	}
	if len(inMiddle) != len(wantMiddle) {
		return false
	}
	for r, count := range inMiddle {
		if wantMiddle[r] != count {
			return false
		}
	}
	return true
}

func boundedLevenshteinDistance(a string, b string, limit int) int {
	ra := []rune(a)
	rb := []rune(b)
	if absInt(len(ra)-len(rb)) > limit {
		return limit + 1
	}
	prev := make([]int, len(rb)+1)
	curr := make([]int, len(rb)+1)
	for j := 0; j <= len(rb); j++ {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		curr[0] = i
		rowMin := curr[0]
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			insertCost := curr[j-1] + 1
			deleteCost := prev[j] + 1
			replaceCost := prev[j-1] + cost
			best := minInt(insertCost, deleteCost)
			best = minInt(best, replaceCost)
			curr[j] = best
			if best < rowMin {
				rowMin = best
			}
		}
		if rowMin > limit {
			return limit + 1
		}
		prev, curr = curr, prev
	}
	if prev[len(rb)] > limit {
		return limit + 1
	}
	return prev[len(rb)]
}
