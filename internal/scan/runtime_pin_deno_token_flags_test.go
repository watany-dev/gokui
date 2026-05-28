package scan

import "testing"

func TestHasShortFlagInCluster(t *testing.T) {
	cases := []struct {
		token string
		flag  byte
		want  bool
	}{
		{token: "-g", flag: 'g', want: true},
		{token: "-gNR", flag: 'g', want: true},
		{token: "-Ngr", flag: 'g', want: false},
		{token: "-Ngr=1", flag: 'g', want: false},
		{token: "-Ngoogle.com", flag: 'g', want: false},
		{token: "-rgithub.com", flag: 'g', want: false},
		{token: "-Igithub.com", flag: 'g', want: false},
		{token: "--global", flag: 'g', want: false},
		{token: "jsr:@std/http", flag: 'g', want: false},
		{token: "-NRE", flag: 'g', want: false},
		{token: "-g=true", flag: 'g', want: true},
	}
	for _, tc := range cases {
		if got := hasShortFlagInCluster(tc.token, tc.flag); got != tc.want {
			t.Fatalf("hasShortFlagInCluster(%q, %q) = %v, want %v", tc.token, tc.flag, got, tc.want)
		}
	}
}

func TestParseBoolLikeToken(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		ok   bool
	}{
		{in: "true", want: true, ok: true},
		{in: "on", want: true, ok: true},
		{in: "1", want: true, ok: true},
		{in: "false", want: false, ok: true},
		{in: "off", want: false, ok: true},
		{in: "0", want: false, ok: true},
		{in: "maybe", want: false, ok: false},
		{in: "", want: false, ok: false},
	}
	for _, tc := range cases {
		got, ok := parseBoolLikeToken(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseBoolLikeToken(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsDenoReloadValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "npm:chalk@5", want: true},
		{value: "jsr:@std/http@1.0.0", want: true},
		{value: "https://example.com/mod.ts", want: true},
		{value: "file:///tmp/mod.ts", want: true},
		{value: "./mod.ts,../other.ts", want: true},
		{value: "npm:chalk@5,jsr:@std/http@1.0.0", want: true},
		{value: "npm:chalk@5,not-a-spec", want: false},
		{value: "not-a-spec", want: false},
	}
	for _, tc := range cases {
		if got := isDenoReloadValue(tc.value); got != tc.want {
			t.Fatalf("isDenoReloadValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoFrozenValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "true", want: true},
		{value: "false", want: true},
		{value: "auto", want: false},
		{value: "1", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoFrozenValue(tc.value); got != tc.want {
			t.Fatalf("isDenoFrozenValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoNoCheckValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "remote", want: true},
		{value: "all", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "https://example.com", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoNoCheckValue(tc.value); got != tc.want {
			t.Fatalf("isDenoNoCheckValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoCoverageValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "coverage", want: true},
		{value: "./cov,./cov2", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "https://example.com", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoCoverageValue(tc.value); got != tc.want {
			t.Fatalf("isDenoCoverageValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoInspectValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "9229", want: true},
		{value: "127.0.0.1:9229", want: true},
		{value: "localhost:9229", want: true},
		{value: "[::1]:9229", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "https://example.com", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoInspectValue(tc.value); got != tc.want {
			t.Fatalf("isDenoInspectValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoWatchValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "src", want: true},
		{value: "src,tests", want: true},
		{value: "./src", want: true},
		{value: "npm:create-vite", want: false},
		{value: "https://example.com", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoWatchValue(tc.value); got != tc.want {
			t.Fatalf("isDenoWatchValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsNumericToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{token: "9229", want: true},
		{token: "0", want: true},
		{token: "92a9", want: false},
		{token: "", want: false},
	}
	for _, tc := range cases {
		if got := isNumericToken(tc.token); got != tc.want {
			t.Fatalf("isNumericToken(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

func TestIsDenoAllowSysValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "hostname", want: true},
		{value: "hostname,osRelease,systemMemoryInfo", want: true},
		{value: "*", want: true},
		{value: "1invalid", want: false},
		{value: "npm:create-vite", want: false},
		{value: ",", want: false},
		{value: "--bad", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowSysValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowSysValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsSysAPIToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{token: "hostname", want: true},
		{token: "osRelease", want: true},
		{token: "systemMemoryInfo", want: true},
		{token: "uid", want: true},
		{token: "1bad", want: false},
		{token: "bad-name", want: false},
		{token: "", want: false},
	}
	for _, tc := range cases {
		if got := isSysApiToken(tc.token); got != tc.want {
			t.Fatalf("isSysApiToken(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}

func TestIsDenoAllowWriteValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: ".", want: true},
		{value: "./out,./cache", want: true},
		{value: "C:\\tmp", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "", want: false},
		{value: "--bad", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowWriteValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowWriteValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoAllowRunValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "deno", want: true},
		{value: "deno,npm", want: true},
		{value: "./bin/tool", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "--bad", want: false},
		{value: ",", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowRunValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowRunValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsDenoAllowFFIValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{value: "./native.so", want: true},
		{value: "./a.so,./b.so", want: true},
		{value: "C:\\native.dll", want: true},
		{value: "npm:create-vite", want: false},
		{value: "jsr:@std/http", want: false},
		{value: "--bad", want: false},
		{value: ",", want: false},
		{value: "", want: false},
	}
	for _, tc := range cases {
		if got := isDenoAllowFFIValue(tc.value); got != tc.want {
			t.Fatalf("isDenoAllowFFIValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}
