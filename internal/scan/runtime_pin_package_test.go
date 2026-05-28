package scan

import "testing"

func TestIsUnpinnedPackageRef(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{ref: "", want: false},
		{ref: "@scope/pkg", want: true},
		{ref: "@scope/pkg@", want: true},
		{ref: "@scope/pkg@latest", want: true},
		{ref: "@scope/pkg@next", want: true},
		{ref: "@scope/pkg@^1.2.3", want: true},
		{ref: "@scope/pkg@1.2.3", want: false},
		{ref: "@scope/pkg@v1.2.3", want: false},
		{ref: "pkg", want: true},
		{ref: "pkg@", want: true},
		{ref: "pkg@latest", want: true},
		{ref: "pkg@beta", want: true},
		{ref: "pkg@~1.2.3", want: true},
		{ref: "pkg@1.2.3", want: false},
	}
	for _, tc := range cases {
		if got := isUnpinnedPackageRef(tc.ref); got != tc.want {
			t.Fatalf("isUnpinnedPackageRef(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestIsUnpinnedLauncherCommand(t *testing.T) {
	t.Run("returns false for unsupported launcher token", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"echo", "safe"}, "echo", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})

	t.Run("returns false when npm exec has no package", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec"}, "npm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})

	t.Run("returns false when pnpm command is not dlx", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"pnpm", "install", "pkg"}, "pnpm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"pnpm", "'--color=always'", "install", "pkg"}, "pnpm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})

	t.Run("accepts normalized launcher token from corepack wrappers", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"corepack", "pnpm@9.0.0", "dlx", "@scope/pkg"}, "pnpm", 1); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"corepack", "'pnpm@9.0.0'", "\"DLX\"", "@scope/pkg"}, "pnpm", 1); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
	})

	t.Run("uses npm exec package flag values", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "tool"}, "npm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec", "--package", "@scope/pkg", "--", "tool"}, "npm", 0); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
	})

	t.Run("uses npx package flag values", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"npx", "-p", "@scope/pkg@1.2.3", "-c", "tool"}, "npx", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"npx", "-p", "@scope/pkg", "-c", "tool"}, "npx", 0); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"npx", "-p@scope/pkg@1.2.3", "-c", "tool"}, "npx", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"npx", "-p@scope/pkg", "-c", "tool"}, "npx", 0); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
	})

	t.Run("ignores npm call flag value as package ref", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec", "--call", "echo hi"}, "npm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})

	t.Run("includes explicit package-like token after separator when package flags are present", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "@scope/other"}, "npm", 0); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "@scope/other@2.0.0"}, "npm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})

	t.Run("applies package-flag and call-flag handling to pnpm/yarn dlx", func(t *testing.T) {
		if got := isUnpinnedLauncherCommand([]string{"pnpm", "dlx", "--package", "@scope/pkg@1.2.3", "--", "@scope/other"}, "pnpm", 0); !got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want true", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"pnpm", "dlx", "--package", "@scope/pkg@1.2.3", "--", "@scope/other@2.0.0"}, "pnpm", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
		if got := isUnpinnedLauncherCommand([]string{"yarn", "dlx", "--call", "echo hi"}, "yarn", 0); got {
			t.Fatalf("isUnpinnedLauncherCommand() = %v, want false", got)
		}
	})
}

func TestExtractPackageRefsFromFlags(t *testing.T) {
	t.Run("extracts package refs from flag forms", func(t *testing.T) {
		fields := []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "-p", "tool@2.0.0", "-p@scope/attached@4.0.0", "--package=other@3.0.0"}
		got := extractPackageRefsFromFlags(fields, 2, len(fields))
		want := []string{"@scope/pkg@1.2.3", "tool@2.0.0", "@scope/attached@4.0.0", "other@3.0.0"}
		if len(got) != len(want) {
			t.Fatalf("extractPackageRefsFromFlags() len = %d, want %d (%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("extractPackageRefsFromFlags()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("ignores missing or invalid package flag values", func(t *testing.T) {
		fields := []string{"npx", "--yes", "--package", "--", "-p=", "--package=", "-c", "tool"}
		got := extractPackageRefsFromFlags(fields, 0, len(fields))
		if len(got) != 0 {
			t.Fatalf("extractPackageRefsFromFlags() = %v, want empty", got)
		}
	})

	t.Run("handles start and end bounds", func(t *testing.T) {
		fields := []string{"npm", "exec", "--package=@scope/pkg@1.2.3"}
		got := extractPackageRefsFromFlags(fields, -10, len(fields)+10)
		if len(got) != 1 || got[0] != "@scope/pkg@1.2.3" {
			t.Fatalf("extractPackageRefsFromFlags() = %v, want [@scope/pkg@1.2.3]", got)
		}

		got = extractPackageRefsFromFlags(fields, 5, 3)
		if got != nil {
			t.Fatalf("extractPackageRefsFromFlags() = %v, want nil for start>=end", got)
		}
	})

	t.Run("extracts attached short package ref", func(t *testing.T) {
		fields := []string{"npx", "-p@scope/pkg@1.2.3", "-c", "tool"}
		got := extractPackageRefsFromFlags(fields, 1, len(fields))
		if len(got) != 1 || got[0] != "@scope/pkg@1.2.3" {
			t.Fatalf("extractPackageRefsFromFlags() = %v, want [@scope/pkg@1.2.3]", got)
		}
	})

	t.Run("extracts quoted package ref flags", func(t *testing.T) {
		fields := []string{"npm", "exec", "'--package=@scope/pkg@1.2.3'", "\"-p@scope/other@2.0.0\"", "--", "tool"}
		got := extractPackageRefsFromFlags(fields, 2, len(fields))
		want := []string{"@scope/pkg@1.2.3", "@scope/other@2.0.0"}
		if len(got) != len(want) {
			t.Fatalf("extractPackageRefsFromFlags() len = %d, want %d (%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("extractPackageRefsFromFlags()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
}

func TestNextNonFlagFieldWithIndex(t *testing.T) {
	t.Run("skips quoted flag tokens", func(t *testing.T) {
		fields := []string{"corepack", "'--install-directory'", "~/.local/bin", "\"pnpm@9.0.0\""}
		got, idx, ok := nextNonFlagFieldWithIndex(fields, 1)
		if !ok || got != "~/.local/bin" || idx != 2 {
			t.Fatalf("nextNonFlagFieldWithIndex(%v, 1) = (%q, %d, %v), want (~/.local/bin, 2, true)", fields, got, idx, ok)
		}
	})

	t.Run("returns sanitized token", func(t *testing.T) {
		fields := []string{"corepack", "\"pnpm@9.0.0\""}
		got, idx, ok := nextNonFlagFieldWithIndex(fields, 1)
		if !ok || got != "pnpm@9.0.0" || idx != 1 {
			t.Fatalf("nextNonFlagFieldWithIndex(%v, 1) = (%q, %d, %v), want (pnpm@9.0.0, 1, true)", fields, got, idx, ok)
		}
	})

	t.Run("returns false when no candidate token exists", func(t *testing.T) {
		fields := []string{"corepack", "--install-directory", "'--cache-dir'"}
		got, idx, ok := nextNonFlagFieldWithIndex(fields, 1)
		if ok || got != "" || idx != -1 {
			t.Fatalf("nextNonFlagFieldWithIndex(%v, 1) = (%q, %d, %v), want (\"\", -1, false)", fields, got, idx, ok)
		}
	})
}

func TestNextRuntimePackageCandidate(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		start  int
		end    int
		want   string
		ok     bool
	}{
		{
			name:   "skips call flag value",
			fields: []string{"npx", "-c", "echo hi"},
			start:  1,
			end:    3,
			want:   "",
			ok:     false,
		},
		{
			name:   "returns package token when present",
			fields: []string{"npm", "exec", "@scope/pkg"},
			start:  2,
			end:    3,
			want:   "@scope/pkg",
			ok:     true,
		},
		{
			name:   "returns first token after separator",
			fields: []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "@scope/other"},
			start:  2,
			end:    6,
			want:   "@scope/other",
			ok:     true,
		},
		{
			name:   "returns false for call equals form",
			fields: []string{"npm", "exec", "--call=echo hi"},
			start:  2,
			end:    3,
			want:   "",
			ok:     false,
		},
		{
			name:   "returns false for attached short call form",
			fields: []string{"npx", "-cecho hi"},
			start:  1,
			end:    2,
			want:   "",
			ok:     false,
		},
		{
			name:   "returns false for quoted attached short call form",
			fields: []string{"npx", "'-cecho hi'"},
			start:  1,
			end:    2,
			want:   "",
			ok:     false,
		},
		{
			name:   "skips package equals flag",
			fields: []string{"npx", "--package=@scope/pkg@1.2.3", "tool"},
			start:  1,
			end:    3,
			want:   "tool",
			ok:     true,
		},
		{
			name:   "returns false when separator has no following token",
			fields: []string{"npm", "exec", "--"},
			start:  2,
			end:    3,
			want:   "",
			ok:     false,
		},
		{
			name:   "clamps out-of-range bounds",
			fields: []string{"npm", "exec", "@scope/pkg"},
			start:  -5,
			end:    99,
			want:   "npm",
			ok:     true,
		},
		{
			name:   "returns false when start is after end",
			fields: []string{"npm", "exec", "@scope/pkg"},
			start:  4,
			end:    2,
			want:   "",
			ok:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nextRuntimePackageCandidate(tc.fields, tc.start, tc.end)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("nextRuntimePackageCandidate(%v) = (%q, %v), want (%q, %v)", tc.fields, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNextExplicitPackageLikeTokenAfterSeparator(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		want   string
		ok     bool
	}{
		{
			name:   "extracts scoped package after separator",
			fields: []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "@scope/other"},
			want:   "@scope/other",
			ok:     true,
		},
		{
			name:   "ignores plain command token after separator",
			fields: []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "tool"},
			want:   "",
			ok:     false,
		},
		{
			name:   "returns false when no separator exists",
			fields: []string{"npm", "exec", "--package", "@scope/pkg@1.2.3"},
			want:   "",
			ok:     false,
		},
		{
			name:   "returns false when separator has no token",
			fields: []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--"},
			want:   "",
			ok:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nextExplicitPackageLikeTokenAfterSeparator(tc.fields, 0, len(tc.fields))
			if ok != tc.ok || got != tc.want {
				t.Fatalf("nextExplicitPackageLikeTokenAfterSeparator(%v) = (%q, %v), want (%q, %v)", tc.fields, got, ok, tc.want, tc.ok)
			}
		})
	}

	t.Run("honors start/end bounds", func(t *testing.T) {
		fields := []string{"npm", "exec", "--package", "@scope/pkg@1.2.3", "--", "@scope/other"}
		got, ok := nextExplicitPackageLikeTokenAfterSeparator(fields, -10, 99)
		if !ok || got != "@scope/other" {
			t.Fatalf("nextExplicitPackageLikeTokenAfterSeparator() = (%q, %v), want (@scope/other, true)", got, ok)
		}

		got, ok = nextExplicitPackageLikeTokenAfterSeparator(fields, 6, 3)
		if ok || got != "" {
			t.Fatalf("nextExplicitPackageLikeTokenAfterSeparator() = (%q, %v), want (\"\", false)", got, ok)
		}
	})
}

func TestIsExplicitPackageLikeRef(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{ref: "@scope/pkg", want: true},
		{ref: "pkg@1.2.3", want: true},
		{ref: "org/pkg", want: true},
		{ref: "tool", want: false},
		{ref: "./tool", want: false},
		{ref: "../tool", want: false},
		{ref: "/tmp/tool", want: false},
		{ref: ".\\tool", want: false},
		{ref: "..\\tool", want: false},
		{ref: "\\tool", want: false},
	}
	for _, tc := range cases {
		if got := isExplicitPackageLikeRef(tc.ref); got != tc.want {
			t.Fatalf("isExplicitPackageLikeRef(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}
