package scan

import "testing"

func TestNextDenoCreatePackage(t *testing.T) {
	cases := []struct {
		name        string
		fields      []string
		start       int
		end         int
		wantPackage string
		wantMode    string
		wantOK      bool
	}{
		{
			name:        "prefixed npm package in auto mode",
			fields:      []string{"deno", "create", "npm:vite"},
			start:       2,
			end:         3,
			wantPackage: "npm:vite",
			wantMode:    "auto",
			wantOK:      true,
		},
		{
			name:        "prefixed jsr package in auto mode",
			fields:      []string{"deno", "create", "jsr:@fresh/init"},
			start:       2,
			end:         3,
			wantPackage: "jsr:@fresh/init",
			wantMode:    "auto",
			wantOK:      true,
		},
		{
			name:        "npm mode with unprefixed package",
			fields:      []string{"deno", "create", "--npm", "create-vite"},
			start:       2,
			end:         4,
			wantPackage: "create-vite",
			wantMode:    "npm",
			wantOK:      true,
		},
		{
			name:        "jsr mode with unprefixed package",
			fields:      []string{"deno", "create", "--jsr", "@fresh/init"},
			start:       2,
			end:         4,
			wantPackage: "@fresh/init",
			wantMode:    "jsr",
			wantOK:      true,
		},
		{
			name:        "separator stops package parsing",
			fields:      []string{"deno", "create", "--npm", "--", "my-app"},
			start:       2,
			end:         5,
			wantPackage: "",
			wantMode:    "npm",
			wantOK:      false,
		},
		{
			name:        "no package returns false",
			fields:      []string{"deno", "create", "--yes"},
			start:       2,
			end:         3,
			wantPackage: "",
			wantMode:    "auto",
			wantOK:      false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotPackage, gotMode, gotOK := nextDenoCreatePackage(tc.fields, tc.start, tc.end)
			if gotPackage != tc.wantPackage || gotMode != tc.wantMode || gotOK != tc.wantOK {
				t.Fatalf("nextDenoCreatePackage(%v, %d, %d) = (%q, %q, %v), want (%q, %q, %v)",
					tc.fields, tc.start, tc.end, gotPackage, gotMode, gotOK, tc.wantPackage, tc.wantMode, tc.wantOK)
			}
		})
	}
}

func TestIsUnpinnedDenoCreatePackageRef(t *testing.T) {
	cases := []struct {
		ref  string
		mode string
		want bool
	}{
		{ref: "npm:vite", mode: "auto", want: true},
		{ref: "npm:vite@6.0.0", mode: "auto", want: false},
		{ref: "jsr:@fresh/init", mode: "auto", want: true},
		{ref: "jsr:@fresh/init@2.3.3", mode: "auto", want: false},
		{ref: "create-vite", mode: "npm", want: true},
		{ref: "create-vite@6.0.0", mode: "npm", want: false},
		{ref: "@fresh/init", mode: "jsr", want: true},
		{ref: "@fresh/init@2.3.3", mode: "jsr", want: false},
		{ref: "fresh-init", mode: "jsr", want: true},
		{ref: "create-vite", mode: "auto", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedDenoCreatePackageRef(tc.ref, tc.mode); got != tc.want {
			t.Fatalf("isUnpinnedDenoCreatePackageRef(%q, %q) = %v, want %v", tc.ref, tc.mode, got, tc.want)
		}
	}
}

func TestIsUnpinnedDenoInitRuntimeLine(t *testing.T) {
	cases := []struct {
		fields []string
		start  int
		end    int
		want   bool
	}{
		{fields: []string{"deno", "init", "my-project"}, start: 2, end: 3, want: false},
		{fields: []string{"deno", "init", "--npm", "vite"}, start: 2, end: 4, want: true},
		{fields: []string{"deno", "init", "--npm", "vite@6.0.0"}, start: 2, end: 4, want: false},
		{fields: []string{"deno", "init", "--jsr", "@fresh/init"}, start: 2, end: 4, want: true},
		{fields: []string{"deno", "init", "--jsr", "@fresh/init@2.3.3"}, start: 2, end: 4, want: false},
		{fields: []string{"deno", "init", "npm:vite"}, start: 2, end: 3, want: true},
		{fields: []string{"deno", "init", "npm:vite@6.0.0"}, start: 2, end: 3, want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedDenoInitRuntimeLine(tc.fields, tc.start, tc.end); got != tc.want {
			t.Fatalf("isUnpinnedDenoInitRuntimeLine(%v, %d, %d) = %v, want %v", tc.fields, tc.start, tc.end, got, tc.want)
		}
	}
}

func TestExtractDenoNpmPackageRefs(t *testing.T) {
	fields := []string{"deno", "x", "-p", "npm:create-vite@5.2.0", "-pnpm:rimraf@5.0.0", "--package=npm:cowsay", "--package", "npm:prettier@3.3.2"}
	got := extractDenoNpmPackageRefs(fields, 2, len(fields))
	want := []string{"npm:create-vite@5.2.0", "npm:rimraf@5.0.0", "npm:cowsay", "npm:prettier@3.3.2"}
	if len(got) != len(want) {
		t.Fatalf("extractDenoNpmPackageRefs() len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extractDenoNpmPackageRefs()[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	t.Run("ignores invalid refs and handles bounds", func(t *testing.T) {
		fields := []string{"deno", "x", "--package", "--", "-p=", "--package="}
		got := extractDenoNpmPackageRefs(fields, -10, 99)
		if len(got) != 0 {
			t.Fatalf("extractDenoNpmPackageRefs() = %v, want empty", got)
		}

		got = extractDenoNpmPackageRefs(fields, 6, 3)
		if got != nil {
			t.Fatalf("extractDenoNpmPackageRefs() = %v, want nil for start>=end", got)
		}
	})

	t.Run("extracts p-equals package ref", func(t *testing.T) {
		fields := []string{"deno", "x", "-p=npm:create-vite@5.2.0"}
		got := extractDenoNpmPackageRefs(fields, 2, len(fields))
		if len(got) != 1 || got[0] != "npm:create-vite@5.2.0" {
			t.Fatalf("extractDenoNpmPackageRefs() = %v, want [npm:create-vite@5.2.0]", got)
		}
	})

	t.Run("extracts attached short package ref", func(t *testing.T) {
		fields := []string{"deno", "x", "-pnpm:create-vite@5.2.0"}
		got := extractDenoNpmPackageRefs(fields, 2, len(fields))
		if len(got) != 1 || got[0] != "npm:create-vite@5.2.0" {
			t.Fatalf("extractDenoNpmPackageRefs() = %v, want [npm:create-vite@5.2.0]", got)
		}
	})

	t.Run("extracts multiple mixed package refs", func(t *testing.T) {
		fields := []string{
			"deno", "x",
			"--package", "npm:create-vite@5.2.0",
			"--package", "jsr:@std/http",
			"-p=jsr:@std/fs@1.0.0",
		}
		got := extractDenoNpmPackageRefs(fields, 2, len(fields))
		want := []string{"npm:create-vite@5.2.0", "jsr:@std/http", "jsr:@std/fs@1.0.0"}
		if len(got) != len(want) {
			t.Fatalf("extractDenoNpmPackageRefs() len = %d, want %d (%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("extractDenoNpmPackageRefs()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestIsUnpinnedDenoNpmSpecifier(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{ref: "npm:create-vite", want: true},
		{ref: "npm:create-vite@", want: true},
		{ref: "npm:create-vite@latest", want: true},
		{ref: "npm:create-vite@5.2.0", want: false},
		{ref: "npm:@scope/tool", want: true},
		{ref: "npm:@scope/tool@next", want: true},
		{ref: "npm:@scope/tool@1.2.3", want: false},
		{ref: "npm:@scope", want: true},
		{ref: "npm:@scope/tool@", want: true},
		{ref: "npm:cowsay@1.5.0/cowthink", want: false},
		{ref: "npm:cowsay/cowthink", want: true},
		{ref: "npm:", want: false},
		{ref: "jsr:@std/http/file-server", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedDenoNpmSpecifier(tc.ref); got != tc.want {
			t.Fatalf("isUnpinnedDenoNpmSpecifier(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestIsUnpinnedDenoRuntimeSpecifier(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{ref: "npm:create-vite", want: true},
		{ref: "npm:create-vite@5.2.0", want: false},
		{ref: "jsr:@std/http/file-server", want: true},
		{ref: "jsr:@std/http@1.0.0/file-server", want: false},
		{ref: "https://example.com/script.ts", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedDenoRuntimeSpecifier(tc.ref); got != tc.want {
			t.Fatalf("isUnpinnedDenoRuntimeSpecifier(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestIsUnpinnedDenoJSRSpecifier(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{ref: "jsr:@std/http/file-server", want: true},
		{ref: "jsr:@std/http@next/file-server", want: true},
		{ref: "jsr:@std/http@1.0.0/file-server", want: false},
		{ref: "jsr:@std", want: true},
		{ref: "jsr:@std/http@", want: true},
		{ref: "jsr:@std/http@", want: true},
		{ref: "jsr:chalk", want: true},
		{ref: "jsr:chalk@1.0.0", want: false},
		{ref: "jsr:chalk@1.0.0/bin", want: false},
		{ref: "jsr:chalk@next/bin", want: true},
		{ref: "jsr:", want: false},
		{ref: "npm:create-vite@latest", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedDenoJSRSpecifier(tc.ref); got != tc.want {
			t.Fatalf("isUnpinnedDenoJSRSpecifier(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}
