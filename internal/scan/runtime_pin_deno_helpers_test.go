package scan

import (
	"strings"
	"testing"
)

func TestDenoOptionalValueValidators(t *testing.T) {
	t.Run("check accepts only all", func(t *testing.T) {
		if !isDenoCheckValue("all") || !isDenoCheckValue(" ALL ") {
			t.Fatalf("isDenoCheckValue should accept all")
		}
		if isDenoCheckValue("none") || isDenoCheckValue("-all") {
			t.Fatalf("isDenoCheckValue should reject non-all or flag-like values")
		}
	})

	t.Run("env-file and tunnel reject remote and flag-like values", func(t *testing.T) {
		if !isDenoEnvFileValue(".env.local") || !isDenoTunnelValue("corp-net") {
			t.Fatalf("expected local env-file/tunnel values to be accepted")
		}
		if isDenoEnvFileValue("https://example.com/.env") || isDenoEnvFileValue("-f") {
			t.Fatalf("expected env-file remote/flag-like values to be rejected")
		}
		if isDenoTunnelValue("npm:tool") || isDenoTunnelValue("-tunnel") {
			t.Fatalf("expected tunnel npm/flag-like values to be rejected")
		}
	})

	t.Run("install-alias accepts safe alias charset only", func(t *testing.T) {
		if !isDenoInstallAliasValue("tool_name-1") {
			t.Fatalf("expected safe alias to be accepted")
		}
		cases := []string{"tool:name", "tool/name", "tool@latest", "npm:tool", ""}
		for _, in := range cases {
			if isDenoInstallAliasValue(in) {
				t.Fatalf("expected alias %q to be rejected", in)
			}
		}
	})
}

func TestShortFlagMayConsumeAttachedValue(t *testing.T) {
	trueCases := []byte{'c', 'e', 'n', 'p', 'L', 'r', 't', 'I', 'R', 'W', 'N', 'E', 'S'}
	for _, flag := range trueCases {
		if !shortFlagMayConsumeAttachedValue(flag) {
			t.Fatalf("expected flag %q to consume attached values", flag)
		}
	}
	if shortFlagMayConsumeAttachedValue('x') {
		t.Fatalf("did not expect flag x to consume attached values")
	}
}

func TestIsPinnedPackageVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: "", want: false},
		{version: "latest", want: false},
		{version: "next", want: false},
		{version: "^1.2.3", want: false},
		{version: "~1.2.3", want: false},
		{version: "1.2.3", want: true},
		{version: "v1.2.3", want: true},
		{version: "1.2.3-beta.1", want: true},
		{version: "v1", want: false},
	}
	for _, tc := range cases {
		if got := isPinnedPackageVersion(tc.version); got != tc.want {
			t.Fatalf("isPinnedPackageVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestIsRemoteDenoRuntimeLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{line: "deno run https://deno.land/x/install.ts", want: true},
		{line: "!deno run https://deno.land/x/install.ts", want: true},
		{line: "$(deno run https://deno.land/x/install.ts)", want: true},
		{line: "&&deno run https://deno.land/x/install.ts", want: true},
		{line: "\"deno\" \"run\" \"https://deno.land/x/install.ts\"", want: true},
		{line: "\\\"deno\\\" \\\"run\\\" \\\"https://deno.land/x/install.ts\\\"", want: true},
		{line: "deno \"install\" -g \"https://deno.land/x/install.ts\"", want: true},
		{line: "&&deno install -g https://deno.land/x/install.ts", want: true},
		{line: "deno install \"-g\" \"https://deno.land/x/install.ts\"", want: true},
		{line: "deno install https://deno.land/x/install.ts", want: false},
		{line: "deno run main.ts", want: false},
		{line: "echo deno run https://deno.land/x/install.ts", want: false},
	}
	for _, tc := range cases {
		if got := isRemoteDenoRuntimeLine(strings.ToLower(tc.line)); got != tc.want {
			t.Fatalf("isRemoteDenoRuntimeLine(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}
