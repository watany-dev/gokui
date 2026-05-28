package scan

import (
	"strings"
	"testing"
	"testing/quick"
	"unicode"
)

func TestNormalizeLauncherToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "pnpm", want: "pnpm"},
		{in: "PNPM@9.0.0", want: "pnpm"},
		{in: "yarn@stable", want: "yarn"},
		{in: "npm@10", want: "npm"},
		{in: "npx@latest", want: "npx"},
		{in: "@scope/pkg@1.2.3", want: "@scope/pkg@1.2.3"},
		{in: "go@1.22.0", want: "go@1.22.0"},
	}
	for _, tc := range cases {
		if got := normalizeLauncherToken(tc.in); got != tc.want {
			t.Fatalf("normalizeLauncherToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeLauncherTokenProperty(t *testing.T) {
	launchers := []string{"npx", "uvx", "bunx", "pnpm", "yarn", "npm"}
	prop := func(idx uint8, suffix string) bool {
		launcher := launchers[int(idx)%len(launchers)]
		var b strings.Builder
		for _, r := range suffix {
			if r > unicode.MaxASCII {
				continue
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '_' {
				b.WriteRune(unicode.ToLower(r))
			}
			if b.Len() >= 32 {
				break
			}
		}
		suffix = b.String()
		if suffix == "" {
			suffix = "latest"
		}
		token := launcher + "@" + suffix
		return normalizeLauncherToken(token) == launcher
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("normalizeLauncherToken property failed: %v", err)
	}
}

func TestSplitCompositeRuntimeToken(t *testing.T) {
	t.Run("splits shell-delimited launcher tokens", func(t *testing.T) {
		left, right, ok := splitCompositeRuntimeToken("'pnpm@9.0.0';\"DLX\"")
		if !ok || left != "pnpm@9.0.0" || right != "dlx" {
			t.Fatalf("splitCompositeRuntimeToken() = (%q, %q, %v), want (pnpm@9.0.0, dlx, true)", left, right, ok)
		}
	})

	t.Run("rejects malformed composite tokens", func(t *testing.T) {
		cases := []string{"pnpm", "pnpm;", ";dlx", ""}
		for _, in := range cases {
			left, right, ok := splitCompositeRuntimeToken(in)
			if ok || left != "" || right != "" {
				t.Fatalf("splitCompositeRuntimeToken(%q) = (%q, %q, %v), want empty/false", in, left, right, ok)
			}
		}
	})
}
