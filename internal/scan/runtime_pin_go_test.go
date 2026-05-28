package scan

import "testing"

func TestNextGoRunTarget(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		start  int
		end    int
		want   string
		ok     bool
	}{
		{
			name:   "finds module target after equals-form flag",
			fields: []string{"go", "run", "-mod=mod", "github.com/acme/x@latest"},
			start:  2,
			end:    4,
			want:   "github.com/acme/x@latest",
			ok:     true,
		},
		{
			name:   "finds module target after split-value flag",
			fields: []string{"go", "run", "-mod", "mod", "github.com/acme/x@latest"},
			start:  2,
			end:    5,
			want:   "github.com/acme/x@latest",
			ok:     true,
		},
		{
			name:   "finds module target after quoted split-value flag",
			fields: []string{"go", "run", "\"-mod\"", "mod", "\"github.com/acme/x@latest\""},
			start:  2,
			end:    5,
			want:   "github.com/acme/x@latest",
			ok:     true,
		},
		{
			name:   "preserves target casing when extracting target",
			fields: []string{"go", "run", "GitHub.com/Acme/X@latest"},
			start:  2,
			end:    3,
			want:   "GitHub.com/Acme/X@latest",
			ok:     true,
		},
		{
			name:   "finds module target after separator",
			fields: []string{"go", "run", "--", "github.com/acme/x@latest"},
			start:  2,
			end:    4,
			want:   "github.com/acme/x@latest",
			ok:     true,
		},
		{
			name:   "returns false when no target",
			fields: []string{"go", "run", "-mod=mod"},
			start:  2,
			end:    3,
			want:   "",
			ok:     false,
		},
		{
			name:   "skips split-value flags and finds later target",
			fields: []string{"go", "run", "-toolexec", "env", "-tags", "dev", "github.com/acme/x@latest"},
			start:  2,
			end:    7,
			want:   "github.com/acme/x@latest",
			ok:     true,
		},
		{
			name:   "returns false when separator has no following token",
			fields: []string{"go", "run", "--"},
			start:  2,
			end:    3,
			want:   "",
			ok:     false,
		},
		{
			name:   "clamps out-of-range bounds",
			fields: []string{"go", "run", "github.com/acme/x@latest"},
			start:  -20,
			end:    50,
			want:   "go",
			ok:     true,
		},
		{
			name:   "returns false when start exceeds end",
			fields: []string{"go", "run", "github.com/acme/x@latest"},
			start:  5,
			end:    3,
			want:   "",
			ok:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nextGoRunTarget(tc.fields, tc.start, tc.end)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("nextGoRunTarget(%v) = (%q, %v), want (%q, %v)", tc.fields, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestFindGoRunArgsStart(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		want   int
		ok     bool
	}{
		{
			name:   "direct go run",
			fields: []string{"go", "run", "github.com/acme/x@latest"},
			want:   2,
			ok:     true,
		},
		{
			name:   "go C-flag before run",
			fields: []string{"go", "-C", "/tmp", "run", "github.com/acme/x@latest"},
			want:   4,
			ok:     true,
		},
		{
			name:   "go C-equals before run",
			fields: []string{"go", "-C=/tmp", "run", "github.com/acme/x@latest"},
			want:   3,
			ok:     true,
		},
		{
			name:   "quoted go run",
			fields: []string{"go", "\"run\"", "github.com/acme/x@latest"},
			want:   2,
			ok:     true,
		},
		{
			name:   "quoted C-flag before quoted run",
			fields: []string{"go", "\"-C\"", "/tmp", "\"run\"", "github.com/acme/x@latest"},
			want:   4,
			ok:     true,
		},
		{
			name:   "other subcommand does not match",
			fields: []string{"go", "test", "./..."},
			want:   -1,
			ok:     false,
		},
		{
			name:   "unknown pre-subcommand flag does not match",
			fields: []string{"go", "-unknown", "run", "github.com/acme/x@latest"},
			want:   -1,
			ok:     false,
		},
		{
			name:   "run without target does not match",
			fields: []string{"go", "run"},
			want:   -1,
			ok:     false,
		},
		{
			name:   "C-flag without value does not match",
			fields: []string{"go", "-C"},
			want:   -1,
			ok:     false,
		},
		{
			name:   "skips empty tokens",
			fields: []string{"go", "", "run", "github.com/acme/x@latest"},
			want:   3,
			ok:     true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := findGoRunArgsStart(tc.fields, 0)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("findGoRunArgsStart(%v) = (%d, %v), want (%d, %v)", tc.fields, got, ok, tc.want, tc.ok)
			}
		})
	}

	t.Run("returns false for invalid go token index", func(t *testing.T) {
		fields := []string{"go", "run", "github.com/acme/x@latest"}
		if got, ok := findGoRunArgsStart(fields, -1); ok || got != -1 {
			t.Fatalf("findGoRunArgsStart(%v, -1) = (%d, %v), want (-1, false)", fields, got, ok)
		}
		if got, ok := findGoRunArgsStart(fields, len(fields)); ok || got != -1 {
			t.Fatalf("findGoRunArgsStart(%v, len) = (%d, %v), want (-1, false)", fields, got, ok)
		}
	})
}

func TestIsUnpinnedGoRunTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{target: "", want: false},
		{target: "main.go", want: false},
		{target: "./cmd/tool", want: false},
		{target: "../cmd/tool", want: false},
		{target: "/abs/path/tool", want: false},
		{target: ".\\cmd\\tool", want: false},
		{target: "..\\cmd\\tool", want: false},
		{target: "\\abs\\path\\tool", want: false},
		{target: "github.com/acme/x", want: true},
		{target: "golang.org/x/tools/cmd/stringer", want: true},
		{target: "github.com/acme/x@latest", want: true},
		{target: "github.com/acme/x@main", want: true},
		{target: "github.com/acme/x@master", want: true},
		{target: "github.com/acme/x@v1", want: true},
		{target: "github.com/acme/x@", want: true},
		{target: "github.com/acme/x@v1.2.3", want: false},
		{target: "github.com/acme/x@v1.2.3-rc.1", want: false},
		{target: "github.com/acme/x@v1.2.3-20260523120000-abcdef123456", want: false},
		{target: "github.com/acme/x@abcdef123456", want: false},
		{target: "fmt", want: false},
		{target: "cmd/tool", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedGoRunTarget(tc.target); got != tc.want {
			t.Fatalf("isUnpinnedGoRunTarget(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

func TestIsPinnedGoModuleVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: "", want: false},
		{version: "latest", want: false},
		{version: "main", want: false},
		{version: "master", want: false},
		{version: "v1", want: false},
		{version: "v1.2.3", want: true},
		{version: "1.2.3", want: true},
		{version: "v1.2.3-rc.1", want: true},
		{version: "v1.2.3+meta", want: true},
		{version: "v1.2.3-20260523120000-abcdef123456", want: true},
		{version: "abcdef123456", want: true},
		{version: "abcdef1", want: false},
	}
	for _, tc := range cases {
		if got := isPinnedGoModuleVersion(tc.version); got != tc.want {
			t.Fatalf("isPinnedGoModuleVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}
