package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyMarkdownLinkSpoofing(t *testing.T) {
	t.Run("detects host mismatch", func(t *testing.T) {
		line := "[https://trusted.example.com/login](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 10)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("does not flag matching host", func(t *testing.T) {
		line := "[https://trusted.example.com/login](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 11)
		if len(findings) != 0 {
			t.Fatalf("expected no findings, got %+v", findings)
		}
	})

	t.Run("does not flag www prefix equivalence", func(t *testing.T) {
		line := "[trusted.example.com](https://www.trusted.example.com/path)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent hosts, got %+v", findings)
		}
	})

	t.Run("does not flag idn and punycode host equivalence", func(t *testing.T) {
		line := "[https://bücher.example/login](https://xn--bcher-kva.example/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent IDN hosts, got %+v", findings)
		}
	})

	t.Run("does not flag trailing-dot host equivalence", func(t *testing.T) {
		line := "[https://trusted.example.com./login](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent trailing-dot hosts, got %+v", findings)
		}
	})

	t.Run("does not flag idna dot-variant host equivalence", func(t *testing.T) {
		line := "[https://trusted。example．com/login](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent IDNA dot-variant hosts, got %+v", findings)
		}
	})

	t.Run("detects idna dot-variant mismatch without scheme in label", func(t *testing.T) {
		line := "[trusted。example．com](https://evil.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("does not flag idna dot-variant equivalence without scheme in label", func(t *testing.T) {
		line := "[trusted。example｡com](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent IDNA dot-variant label host, got %+v", findings)
		}
	})

	t.Run("detects mismatch for scheme-relative display host label", func(t *testing.T) {
		line := "[//trusted.example.com/login](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("does not flag equivalence for scheme-relative display host label", func(t *testing.T) {
		line := "[//trusted.example.com/login](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent scheme-relative display host, got %+v", findings)
		}
	})

	t.Run("does not flag trailing idna dot-variant host equivalence", func(t *testing.T) {
		line := "[https://trusted.example.com。/login](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 12)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent trailing IDNA dot-variant hosts, got %+v", findings)
		}
	})

	t.Run("ignores non-host labels", func(t *testing.T) {
		line := "[click here](https://trusted.example.com/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for non-host label, got %+v", findings)
		}
	})

	t.Run("ignores image markdown forms", func(t *testing.T) {
		line := "![https://trusted.example.com/login](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for image markdown, got %+v", findings)
		}
	})

	t.Run("does not treat escaped image marker as image markdown", func(t *testing.T) {
		line := `\![https://trusted.example.com/login](https://evil.example.net/login)`
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("handles angle-bracketed display URLs", func(t *testing.T) {
		line := "[<https://trusted.example.com/login>](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[<https://trusted.example.com/login>](https://trusted.example.com/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent angle-bracketed display URL, got %+v", findings)
		}
	})

	t.Run("handles inline-code display URLs", func(t *testing.T) {
		line := "[`https://trusted.example.com/login`](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[`https://trusted.example.com/login`](https://trusted.example.com/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent inline-code display URL, got %+v", findings)
		}
	})

	t.Run("handles emphasis-wrapped display URLs", func(t *testing.T) {
		line := "[**https://trusted.example.com/login**](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[_https://trusted.example.com/login_](https://evil.example.net/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[__https://trusted.example.com/login__](https://trusted.example.com/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent emphasis-wrapped display URL, got %+v", findings)
		}
	})

	t.Run("handles nested wrappers around display URLs", func(t *testing.T) {
		line := "[**<https://trusted.example.com/login>**](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[`<https://trusted.example.com/login>`](https://evil.example.net/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[`<https://trusted.example.com/login>`](https://trusted.example.com/login)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent nested-wrapper display URL, got %+v", findings)
		}
	})

	t.Run("handles markdown link targets with titles", func(t *testing.T) {
		line := "[https://trusted.example.com/login](https://evil.example.net/login \"reference docs\")"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[https://trusted.example.com/login](https://trusted.example.com/login \"reference docs\")"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent markdown link target with title, got %+v", findings)
		}

		line = "[https://trusted.example.com/login](<https://evil.example.net/login> \"reference docs\")"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("handles targets with balanced parentheses", func(t *testing.T) {
		line := "[https://trusted.example.com/login](https://evil.example.net/path_(x))"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")

		line = "[https://trusted.example.com/login](https://trusted.example.com/path_(x))"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 13)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent host with balanced-parentheses target, got %+v", findings)
		}
	})

	t.Run("ignores malformed display or target URLs", func(t *testing.T) {
		line := "[https://trusted.example.com/%zz](https://evil.example.net/login)"
		findings := classifyMarkdownLinkSpoofing(line, "SKILL.md", 14)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for malformed display URL, got %+v", findings)
		}

		line = "[https://trusted.example.com/login](https://evil.example.net/%zz)"
		findings = classifyMarkdownLinkSpoofing(line, "SKILL.md", 15)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for malformed target URL, got %+v", findings)
		}
	})
}

func TestClassifyMarkdownReferenceLinkSpoofing(t *testing.T) {
	t.Run("returns no findings for empty reference index", func(t *testing.T) {
		line := "[https://trusted.example.com/login][auth]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, map[string]string{})
		if len(findings) != 0 {
			t.Fatalf("expected no findings for empty reference map, got %+v", findings)
		}
	})

	t.Run("detects full reference link host mismatch", func(t *testing.T) {
		references := map[string]string{
			"auth": "evil.example.net",
		}
		line := "[https://trusted.example.com/login][auth]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("does not flag equivalent full reference link host", func(t *testing.T) {
		references := map[string]string{
			"auth": "trusted.example.com",
		}
		line := "[https://trusted.example.com/login][auth]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent full reference link host, got %+v", findings)
		}
	})

	t.Run("resolves collapsed reference using label text", func(t *testing.T) {
		references := map[string]string{
			"https://trusted.example.com/login": "evil.example.net",
		}
		line := "[https://trusted.example.com/login][]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("ignores reference-style image forms", func(t *testing.T) {
		references := map[string]string{
			"auth": "evil.example.net",
		}
		line := "![https://trusted.example.com/login][auth]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for reference-style images, got %+v", findings)
		}
	})

	t.Run("does not treat escaped reference image marker as image markdown", func(t *testing.T) {
		references := map[string]string{
			"auth": "evil.example.net",
		}
		line := `\![https://trusted.example.com/login][auth]`
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("detects shortcut reference link mismatch", func(t *testing.T) {
		references := map[string]string{
			"https://trusted.example.com/login": "evil.example.net",
		}
		line := "Use [https://trusted.example.com/login] before setup."
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})

	t.Run("does not flag equivalent shortcut reference link host", func(t *testing.T) {
		references := map[string]string{
			"https://trusted.example.com/login": "trusted.example.com",
		}
		line := "Use [https://trusted.example.com/login] before setup."
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for equivalent shortcut reference link host, got %+v", findings)
		}
	})

	t.Run("ignores reference definition lines", func(t *testing.T) {
		references := map[string]string{
			"https://trusted.example.com/login": "evil.example.net",
		}
		line := "[https://trusted.example.com/login]: https://evil.example.net/login"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for reference definition line, got %+v", findings)
		}
	})

	t.Run("ignores inline and full-reference forms in shortcut matcher", func(t *testing.T) {
		references := map[string]string{
			"https://trusted.example.com/login": "evil.example.net",
		}
		line := "[https://trusted.example.com/login](https://evil.example.net/login)"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for inline-style markdown links, got %+v", findings)
		}

		line = "[https://trusted.example.com/login][auth]"
		findings = classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for full reference form without matching ref ID, got %+v", findings)
		}

		line = "[https://trusted.example.com/login] (https://evil.example.net/login)"
		findings = classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for spaced inline-style markdown links, got %+v", findings)
		}

		line = "[https://trusted.example.com/login] [auth]"
		findings = classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for spaced full-reference markdown links, got %+v", findings)
		}

		line = "[https://trusted.example.com/login] : https://evil.example.net/login"
		findings = classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		if len(findings) != 0 {
			t.Fatalf("expected no findings for spaced reference-definition markdown lines, got %+v", findings)
		}
	})

	t.Run("detects spaced full reference link host mismatch", func(t *testing.T) {
		references := map[string]string{
			"auth": "evil.example.net",
		}
		line := "[https://trusted.example.com/login] [auth]"
		findings := classifyMarkdownReferenceLinkSpoofing(line, "SKILL.md", 20, references)
		assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
	})
}

func TestBuildMarkdownReferenceHostIndex(t *testing.T) {
	lines := []string{
		"[Auth Ref]: https://trusted.example.com/login",
		"[auth ref]: https://evil.example.net/login",
		"[ docs ]: <https://docs.example.net/guide> \"title\"",
		"[split]:",
		"https://split.example.net/docs \"split title\"",
		"[   ]: https://ignored.example.net",
		"[invalid]: mailto:security@example.com",
	}

	hosts := buildMarkdownReferenceHostIndex(lines)
	if got := hosts["auth ref"]; got != "trusted.example.com" {
		t.Fatalf("expected first duplicate reference host to win, got %q", got)
	}
	if got := hosts["docs"]; got != "docs.example.net" {
		t.Fatalf("expected angle-bracket reference host parse, got %q", got)
	}
	if got := hosts["split"]; got != "split.example.net" {
		t.Fatalf("expected multiline reference host parse, got %q", got)
	}
	if _, ok := hosts["invalid"]; ok {
		t.Fatalf("expected non-http reference target to be ignored")
	}
}

func TestNormalizeMarkdownReferenceID(t *testing.T) {
	if got := normalizeMarkdownReferenceID("  Auth\tRef  "); got != "auth ref" {
		t.Fatalf("expected collapsed lowercase reference ID, got %q", got)
	}
	if got := normalizeMarkdownReferenceID(" \t "); got != "" {
		t.Fatalf("expected empty reference ID for whitespace input, got %q", got)
	}
}

func TestBuildMarkdownReferenceUsageContinuationVariant(t *testing.T) {
	t.Run("joins adjacent lines for full reference usage", func(t *testing.T) {
		lines := []string{
			"Use [https://trusted.example.com/login]",
			"[auth] before setup",
		}
		got, ok := buildMarkdownReferenceUsageContinuationVariant(lines, 0)
		if !ok {
			t.Fatalf("expected continuation variant to be built")
		}
		if got != "Use [https://trusted.example.com/login] [auth] before setup" {
			t.Fatalf("unexpected continuation variant: %q", got)
		}
	})

	t.Run("skips empty, out-of-range, and definition-like next lines", func(t *testing.T) {
		if _, ok := buildMarkdownReferenceUsageContinuationVariant([]string{"only one line"}, 0); ok {
			t.Fatalf("expected no continuation variant for single-line input")
		}
		if _, ok := buildMarkdownReferenceUsageContinuationVariant([]string{"Use [x]", ""}, 0); ok {
			t.Fatalf("expected no continuation variant for empty next line")
		}
		if _, ok := buildMarkdownReferenceUsageContinuationVariant([]string{"Use [x]", "[auth]: https://example.com"}, 0); ok {
			t.Fatalf("expected no continuation variant for reference-definition next line")
		}
		if _, ok := buildMarkdownReferenceUsageContinuationVariant([]string{"plain text", "[auth]"}, 0); ok {
			t.Fatalf("expected no continuation variant when current line lacks closing bracket")
		}
	})
}

func TestUnwrapMarkdownEmphasis(t *testing.T) {
	t.Run("unwraps supported outer emphasis markers", func(t *testing.T) {
		if got := unwrapMarkdownEmphasis("**https://trusted.example.com/login**"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected double-asterisk unwrap, got %q", got)
		}
		if got := unwrapMarkdownEmphasis("__https://trusted.example.com/login__"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected double-underscore unwrap, got %q", got)
		}
		if got := unwrapMarkdownEmphasis("*https://trusted.example.com/login*"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected single-asterisk unwrap, got %q", got)
		}
		if got := unwrapMarkdownEmphasis("_https://trusted.example.com/login_"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected single-underscore unwrap, got %q", got)
		}
	})

	t.Run("keeps malformed or non-emphasis values unchanged", func(t *testing.T) {
		if got := unwrapMarkdownEmphasis("*https://trusted.example.com/login**"); got != "*https://trusted.example.com/login**" {
			t.Fatalf("expected mismatched markers to remain unchanged, got %q", got)
		}
		if got := unwrapMarkdownEmphasis("**"); got != "**" {
			t.Fatalf("expected short marker-only value to remain unchanged, got %q", got)
		}
		if got := unwrapMarkdownEmphasis("https://trusted.example.com/login"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected plain value to remain unchanged, got %q", got)
		}
	})
}

func TestUnwrapDisplayLinkLabel(t *testing.T) {
	t.Run("unwraps nested code emphasis and angle wrappers", func(t *testing.T) {
		got := unwrapDisplayLinkLabel(" **`<https://trusted.example.com/login>`** ")
		if got != "https://trusted.example.com/login" {
			t.Fatalf("expected fully unwrapped display label, got %q", got)
		}
	})

	t.Run("returns original value when no wrappers are present", func(t *testing.T) {
		got := unwrapDisplayLinkLabel("https://trusted.example.com/login")
		if got != "https://trusted.example.com/login" {
			t.Fatalf("expected unchanged display label, got %q", got)
		}
	})
}

func TestExtractMarkdownLinkTargetURL(t *testing.T) {
	t.Run("extracts first token target URL", func(t *testing.T) {
		got, ok := extractMarkdownLinkTargetURL(`https://evil.example.net/login "reference docs"`)
		if !ok {
			t.Fatalf("expected URL extraction to succeed")
		}
		if got != "https://evil.example.net/login" {
			t.Fatalf("expected first token URL, got %q", got)
		}
	})

	t.Run("extracts angle-bracketed target URL", func(t *testing.T) {
		got, ok := extractMarkdownLinkTargetURL(`<https://evil.example.net/login> 'reference docs'`)
		if !ok {
			t.Fatalf("expected angle-bracket URL extraction to succeed")
		}
		if got != "https://evil.example.net/login" {
			t.Fatalf("expected bracket URL, got %q", got)
		}
	})

	t.Run("rejects empty and malformed angle target URL", func(t *testing.T) {
		if _, ok := extractMarkdownLinkTargetURL("   "); ok {
			t.Fatalf("expected extraction failure for empty target")
		}
		if _, ok := extractMarkdownLinkTargetURL("<> \"title\""); ok {
			t.Fatalf("expected extraction failure for empty angle target")
		}
	})
}

func TestParseMarkdownLinkTargetHost(t *testing.T) {
	t.Run("parses scheme-relative target host", func(t *testing.T) {
		got, ok := parseMarkdownLinkTargetHost("//evil.example.net/login")
		if !ok {
			t.Fatalf("expected scheme-relative host parse to succeed")
		}
		if got != "evil.example.net" {
			t.Fatalf("expected host evil.example.net, got %q", got)
		}
	})

	t.Run("ignores non-http target URL", func(t *testing.T) {
		if _, ok := parseMarkdownLinkTargetHost("mailto:security@example.com"); ok {
			t.Fatalf("expected non-http target to be ignored")
		}
	})

	t.Run("parses angle-bracketed target host with title", func(t *testing.T) {
		got, ok := parseMarkdownLinkTargetHost(`<evil.example.net> "reference docs"`)
		if ok {
			t.Fatalf("expected invalid angle target URL to be ignored, got host %q", got)
		}

		got, ok = parseMarkdownLinkTargetHost(`<https://evil.example.net/login> "reference docs"`)
		if !ok {
			t.Fatalf("expected angle-bracketed http target host parse to succeed")
		}
		if got != "evil.example.net" {
			t.Fatalf("expected host evil.example.net, got %q", got)
		}
	})

	t.Run("rejects empty or malformed target forms", func(t *testing.T) {
		if _, ok := parseMarkdownLinkTargetHost("   "); ok {
			t.Fatalf("expected empty target to be ignored")
		}
		if _, ok := parseMarkdownLinkTargetHost(`<https://evil.example.net/login "reference docs"`); ok {
			t.Fatalf("expected malformed angle target to be ignored")
		}
	})
}

func TestUnwrapMarkdownCodeSpan(t *testing.T) {
	t.Run("unwraps single and multiple backtick fences", func(t *testing.T) {
		if got := unwrapMarkdownCodeSpan("`https://trusted.example.com/login`"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected single-backtick unwrap, got %q", got)
		}
		if got := unwrapMarkdownCodeSpan("```https://trusted.example.com/login```"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected triple-backtick unwrap, got %q", got)
		}
	})

	t.Run("returns original for non-code or malformed fences", func(t *testing.T) {
		if got := unwrapMarkdownCodeSpan("https://trusted.example.com/login"); got != "https://trusted.example.com/login" {
			t.Fatalf("expected unchanged non-code span, got %q", got)
		}
		if got := unwrapMarkdownCodeSpan("``"); got != "``" {
			t.Fatalf("expected unchanged short fence, got %q", got)
		}
		if got := unwrapMarkdownCodeSpan("``https://trusted.example.com/login`"); got != "``https://trusted.example.com/login`" {
			t.Fatalf("expected unchanged mismatched fence, got %q", got)
		}
	})
}
func TestScanSkillRootDetectsReferenceStyleLinkSpoofing(t *testing.T) {
	root := t.TempDir()
	content := `# Skill
Use [https://trusted.example.com/login][auth] before setup.

[auth]: https://evil.example.net/login "auth docs"
`
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
}

func TestScanSkillRootDetectsSpacedReferenceStyleLinkSpoofing(t *testing.T) {
	root := t.TempDir()
	content := `# Skill
Use [https://trusted.example.com/login] [auth] before setup.

[auth]: https://evil.example.net/login "auth docs"
`
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
}

func TestScanSkillRootDetectsMultilineReferenceDefinitionLinkSpoofing(t *testing.T) {
	root := t.TempDir()
	content := `# Skill
Use [https://trusted.example.com/login][auth] before setup.

[auth]:
https://evil.example.net/login "auth docs"
`
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
}

func TestScanSkillRootDetectsShortcutReferenceLinkSpoofing(t *testing.T) {
	root := t.TempDir()
	content := `# Skill
Use [https://trusted.example.com/login] before setup.

[https://trusted.example.com/login]: https://evil.example.net/login "auth docs"
`
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}

	findings, err := ScanSkillRoot(root)
	if err != nil {
		t.Fatalf("ScanSkillRoot() error = %v", err)
	}
	assertHasID(t, findings, "LINK_SPOOFING_URL_MISMATCH")
}
