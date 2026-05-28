package scan

import "testing"

func TestIsDenoReloadBlocklistValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "npm:chalk", want: true},
		{value: "jsr:@std/http@1.0.0", want: true},
		{value: "https://deno.land/std@0.224.0/fs/copy.ts", want: true},
		{value: "file:./mod.ts", want: true},
		{value: "./mod.ts", want: true},
		{value: "../mod.ts", want: true},
		{value: "/tmp/mod.ts", want: true},
		{value: "main.ts", want: false},
		{value: "true", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoReloadBlocklistValue(tc.value); got != tc.want {
			t.Fatalf("isDenoReloadBlocklistValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoAllowScriptsValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "sqlite3", want: true},
		{value: "@scope/pkg", want: true},
		{value: "sqlite3,@scope/pkg", want: true},
		{value: "npm:sqlite3", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "https://example.com/mod.ts", want: false},
		{value: "./local", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowScriptsValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowScriptsValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsScopedOrPackageRefToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{token: "sqlite3", want: true},
		{token: "@scope/pkg", want: true},
		{token: "pkg_name-1.2.3", want: true},
		{token: "npm:sqlite3", want: false},
		{token: "pkg name", want: false},
		{token: "", want: false},
	}
	for _, tc := range cases {
		if got := isScopedOrPackageRefToken(tc.token); got != tc.want {
			t.Fatalf("isScopedOrPackageRefToken(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

func TestIsDenoAllowImportValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "deno.land", want: true},
		{value: "deno.land:443", want: true},
		{value: "*.example.com", want: true},
		{value: "https://deno.land", want: true},
		{value: "http://deno.land", want: true},
		{value: "[::1]:443", want: true},
		{value: "deno.land,jsr.io:443", want: true},
		{value: "deno.land,", want: false},
		{value: "--bad", want: false},
		{value: "npm:create-vite", want: false},
		{value: "local-file", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowImportValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowImportValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsHostLikeToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{token: "deno.land", want: true},
		{token: "deno.land:443", want: true},
		{token: "*.example.com", want: true},
		{token: "*.example.com:443", want: true},
		{token: "[::1]:443", want: true},
		{token: "[::1]", want: true},
		{token: "[::1]:", want: false},
		{token: "[::1]abc", want: false},
		{token: "[::1", want: false},
		{token: "deno.land:abc", want: false},
		{token: "deno.land:", want: false},
		{token: "example..com", want: true},
		{token: "localhost", want: false},
		{token: "npm:create-vite", want: false},
		{token: "exa_mple.com", want: false},
		{token: "bad host", want: false},
	}
	for _, tc := range cases {
		if got := isHostLikeToken(tc.token); got != tc.want {
			t.Fatalf("isHostLikeToken(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

func TestIsDenoAllowReadValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: ".", want: true},
		{value: "./dir,../other", want: true},
		{value: "C:\\tmp", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
		{value: ",", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowReadValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowReadValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoAllowNetValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "deno.land", want: true},
		{value: "1.1.1.1:443", want: true},
		{value: "*.example.com", want: true},
		{value: "npm:create-vite", want: false},
		{value: "local-path", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowNetValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowNetValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoAllowEnvValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "PATH", want: true},
		{value: "HOME,PATH", want: true},
		{value: "*", want: true},
		{value: "1INVALID", want: false},
		{value: "BAD-NAME", want: false},
		{value: "--bad", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowEnvValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowEnvValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
