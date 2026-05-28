package scan

import "testing"

func TestClassifyPathRisks(t *testing.T) {
	t.Run("detects mixed script and confusable filename risks", func(t *testing.T) {
		findings := classifyPathRisks("docs/pay\u0440al.md")
		assertHasID(t, findings, "MIXED_SCRIPT_FILENAME")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")
		for _, finding := range findings {
			if finding.ID == "MIXED_SCRIPT_FILENAME" && finding.Severity != "medium" {
				t.Fatalf("expected medium severity for mixed-script finding, got %q", finding.Severity)
			}
			if finding.ID == "CONFUSABLE_FILENAME" && finding.Severity != "high" {
				t.Fatalf("expected high severity for confusable filename finding, got %q", finding.Severity)
			}
		}
	})

	t.Run("mixed script without confusable glyph does not raise confusable finding", func(t *testing.T) {
		findings := classifyPathRisks("docs/alpha\u0416.md")
		assertHasID(t, findings, "MIXED_SCRIPT_FILENAME")
		for _, finding := range findings {
			if finding.ID == "CONFUSABLE_FILENAME" {
				t.Fatalf("unexpected confusable finding: %+v", finding)
			}
		}
	})

	t.Run("detects fullwidth ascii confusable filename", func(t *testing.T) {
		findings := classifyPathRisks("docs/payｐal.md")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")
	})

	t.Run("detects compatibility-style confusable filename", func(t *testing.T) {
		findings := classifyPathRisks("docs/pay𝐩al.md")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")
	})

	t.Run("detects compatibility-only filename token", func(t *testing.T) {
		findings := classifyPathRisks("docs/ｐａｙｐａｌ.md")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/readme．ｍｄ")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/ｐａｙｐａｌ．ｍｄ")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")
	})

	t.Run("detects dot-like confusable separators", func(t *testing.T) {
		cases := []string{
			"docs/readme․md",
			"docs/readme。md",
		}
		for _, path := range cases {
			findings := classifyPathRisks(path)
			assertHasID(t, findings, "CONFUSABLE_FILENAME")
		}
	})

	t.Run("detects confusable and mixed-script directory names", func(t *testing.T) {
		findings := classifyPathRisks("docs/pay𝐩al/readme.md")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/payрal/readme.md")
		assertHasID(t, findings, "MIXED_SCRIPT_FILENAME")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")
	})

	t.Run("detects confusable extension names", func(t *testing.T) {
		findings := classifyPathRisks("docs/readme.mе")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/readme.mԁ")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/readme.ｍｄ")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/тест.mе")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/.ｍｄ")
		assertHasID(t, findings, "CONFUSABLE_FILENAME")

		findings = classifyPathRisks("docs/readme.①②")
		for _, finding := range findings {
			if finding.ID == "CONFUSABLE_FILENAME" {
				t.Fatalf("unexpected confusable finding for numeric-only compatibility extension: %+v", finding)
			}
		}
	})

	t.Run("detects additional cyrillic confusable glyphs", func(t *testing.T) {
		cases := []string{
			"docs/sһell.md",
			"docs/tooӏs.md",
			"docs/neԝs.md",
			"docs/doϲs.md",
			"docs/DoϹs.md",
		}
		for _, path := range cases {
			findings := classifyPathRisks(path)
			assertHasID(t, findings, "CONFUSABLE_FILENAME")
		}
	})

	t.Run("ignores single script or non-letter separators", func(t *testing.T) {
		cases := []string{
			"docs/paypal.md",
			"docs/\u0442\u0435\u0441\u0442.md",
			"docs/①②.md",
			"docs/123-test.md",
			"docs/.\u0442\u0435\u0441\u0442",
		}
		for _, path := range cases {
			if findings := classifyPathRisks(path); len(findings) != 0 {
				t.Fatalf("expected no findings for %q, got %+v", path, findings)
			}
		}
	})
}

func TestPathRiskComponents(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{path: "docs/paypal.md", want: []string{"docs", "paypal"}},
		{path: "./docs//nested/readme.md", want: []string{"docs", "nested", "readme"}},
		{path: "../docs/.hidden", want: []string{"docs", ".hidden"}},
		{path: "docs/archive.tar.gz", want: []string{"docs", "archive.tar"}},
		{path: "", want: nil},
	}
	for _, tc := range cases {
		got := pathRiskComponents(tc.path)
		if len(got) != len(tc.want) {
			t.Fatalf("pathRiskComponents(%q) len = %d, want %d (%v)", tc.path, len(got), len(tc.want), got)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("pathRiskComponents(%q)[%d] = %q, want %q", tc.path, i, got[i], tc.want[i])
			}
		}
	}
}

func TestPathRiskRawComponents(t *testing.T) {
	cases := []struct {
		path string
		want []string
	}{
		{path: "docs/paypal.md", want: []string{"docs", "paypal.md"}},
		{path: "./docs//nested/readme.md", want: []string{"docs", "nested", "readme.md"}},
		{path: "../docs/.hidden", want: []string{"docs", ".hidden"}},
		{path: "docs/ payрal .md", want: []string{"docs", " payрal .md"}},
		{path: "", want: nil},
	}
	for _, tc := range cases {
		got := pathRiskRawComponents(tc.path)
		if len(got) != len(tc.want) {
			t.Fatalf("pathRiskRawComponents(%q) len = %d, want %d (%v)", tc.path, len(got), len(tc.want), got)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("pathRiskRawComponents(%q)[%d] = %q, want %q", tc.path, i, got[i], tc.want[i])
			}
		}
	}
}

func TestHasConfusableExtension(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "readme.mе", want: true},
		{value: "readme.ｍｄ", want: true},
		{value: ".ｍｄ", want: true},
		{value: "readme.①②", want: false},
		{value: "readme.", want: false},
		{value: "readme.md", want: false},
		{value: ".git", want: false},
		{value: "readme", want: false},
		{value: "тест.mе", want: true},
	}
	for _, tc := range cases {
		if got := hasConfusableExtension(tc.value); got != tc.want {
			t.Fatalf("hasConfusableExtension(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsNFKCASCIIAlnumToken(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "ｍｄ", want: true},
		{value: "①②", want: true},
		{value: "md", want: false},
		{value: "тест", want: false},
		{value: "㋐", want: false},
		{value: "＋", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isNFKCASCIIAlnumToken(tc.value); got != tc.want {
			t.Fatalf("isNFKCASCIIAlnumToken(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsNFKCASCIILetterToken(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "ｍｄ", want: true},
		{value: "①②", want: false},
		{value: "md", want: false},
		{value: "＋", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isNFKCASCIILetterToken(tc.value); got != tc.want {
			t.Fatalf("isNFKCASCIILetterToken(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsNFKCNonASCIIFilenameLikeToken(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "ｐａｙｐａｌ．ｍｄ", want: true},
		{value: "readme．ｍｄ", want: false},
		{value: "тест", want: false},
		{value: "ｐａｙ＊", want: false},
		{value: "１２３", want: false},
		{value: "①②", want: false},
		{value: "ｍｄ", want: true},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isNFKCNonASCIIFilenameLikeToken(tc.value); got != tc.want {
			t.Fatalf("isNFKCNonASCIIFilenameLikeToken(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsNFKCASCIIAlnumConfusable(t *testing.T) {
	t.Run("detects compatibility letters and digits", func(t *testing.T) {
		cases := []rune{'𝐩', '𝟎', 'ⓐ'}
		for _, r := range cases {
			if !isNFKCASCIIAlnumConfusable(r) {
				t.Fatalf("expected compatibility confusable for %q", string(r))
			}
		}
	})

	t.Run("ignores ascii and non-ascii non-alnum normalization", func(t *testing.T) {
		cases := []rune{'a', 'あ', '・', '㍑', '﹢'}
		for _, r := range cases {
			if isNFKCASCIIAlnumConfusable(r) {
				t.Fatalf("unexpected compatibility confusable for %q", string(r))
			}
		}
	})
}

func TestIsFullwidthASCIIConfusable(t *testing.T) {
	t.Run("detects fullwidth digits and letters", func(t *testing.T) {
		cases := []rune{'０', 'Ａ', 'ｚ'}
		for _, r := range cases {
			if !isFullwidthASCIIConfusable(r) {
				t.Fatalf("expected fullwidth confusable for %q", string(r))
			}
		}
	})

	t.Run("ignores non-fullwidth runes", func(t *testing.T) {
		cases := []rune{'A', 'あ', 'ⓐ'}
		for _, r := range cases {
			if isFullwidthASCIIConfusable(r) {
				t.Fatalf("unexpected fullwidth confusable for %q", string(r))
			}
		}
	})
}

func TestIsDotLikeConfusable(t *testing.T) {
	trueCases := []rune{'．', '｡', '。', '﹒', '․'}
	for _, r := range trueCases {
		if !isDotLikeConfusable(r) {
			t.Fatalf("expected dot-like confusable for %q", string(r))
		}
	}

	falseCases := []rune{'.', 'a', '1', '・'}
	for _, r := range falseCases {
		if isDotLikeConfusable(r) {
			t.Fatalf("unexpected dot-like confusable for %q", string(r))
		}
	}
}
