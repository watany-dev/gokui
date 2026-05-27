package scan

import "testing"

func TestIsKnownDenoOptionalFlagValue(t *testing.T) {
	t.Run("reload value requires following candidate", func(t *testing.T) {
		fields := []string{"deno", "run", "--reload", "npm:chalk@5"}
		if got := isKnownDenoOptionalFlagValue("--reload", "npm:chalk@5", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--reload) = %v, want false", got)
		}
	})

	t.Run("reload accepts blocklist value when following target exists", func(t *testing.T) {
		fields := []string{"deno", "run", "--reload", "npm:chalk@5", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--reload", "npm:chalk@5", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--reload) = %v, want true", got)
		}
	})

	t.Run("reload rejects invalid blocklist value", func(t *testing.T) {
		fields := []string{"deno", "run", "--reload", "not-a-spec", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--reload", "not-a-spec", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--reload) = %v, want false", got)
		}
	})

	t.Run("reload accepts comma-separated blocklist values", func(t *testing.T) {
		fields := []string{"deno", "run", "--reload", "npm:chalk,jsr:@std/http@1.0.0", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--reload", "npm:chalk,jsr:@std/http@1.0.0", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--reload) = %v, want true", got)
		}
	})

	t.Run("vendor accepts boolean strings only", func(t *testing.T) {
		fields := []string{"deno", "run"}
		if got := isKnownDenoOptionalFlagValue("--vendor", "true", fields, 0, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--vendor,true) = %v, want true", got)
		}
		if got := isKnownDenoOptionalFlagValue("--vendor", "false", fields, 0, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--vendor,false) = %v, want true", got)
		}
		if got := isKnownDenoOptionalFlagValue("--vendor", "auto", fields, 0, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--vendor,auto) = %v, want false", got)
		}
	})

	t.Run("node-modules-dir validates mode", func(t *testing.T) {
		fields := []string{"deno", "run"}
		if got := isKnownDenoOptionalFlagValue("--node-modules-dir", "auto", fields, 0, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--node-modules-dir,auto) = %v, want true", got)
		}
		if got := isKnownDenoOptionalFlagValue("--node-modules-dir", "manual", fields, 0, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--node-modules-dir,manual) = %v, want true", got)
		}
		if got := isKnownDenoOptionalFlagValue("--node-modules-dir", "garbage", fields, 0, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--node-modules-dir,garbage) = %v, want false", got)
		}
	})

	t.Run("allow-scripts consumes package-like value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-scripts", "sqlite3", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-scripts", "sqlite3", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-scripts,sqlite3) = %v, want true", got)
		}
	})

	t.Run("allow-scripts rejects ambiguous or invalid values", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-scripts", "sqlite3", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-scripts", "npm:sqlite3", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-scripts,npm:sqlite3) = %v, want false", got)
		}
		if got := isKnownDenoOptionalFlagValue("--allow-scripts", "./local", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-scripts,./local) = %v, want false", got)
		}
	})

	t.Run("allow-import consumes host value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-import", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-import", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-import,deno.land) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-I", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-I", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-I,deno.land) = %v, want true", got)
		}
	})

	t.Run("env-file consumes value only when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--env-file", ".env", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--env-file", ".env", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--env-file,.env) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--env-file", ".env"}
		if got := isKnownDenoOptionalFlagValue("--env-file", ".env", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--env-file,.env) = %v, want false", got)
		}
	})

	t.Run("lock consumes value only when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--lock", "deno.lock", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--lock", "deno.lock", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--lock,deno.lock) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--lock", "deno.lock"}
		if got := isKnownDenoOptionalFlagValue("--lock", "deno.lock", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--lock,deno.lock) = %v, want false", got)
		}
		if got := isKnownDenoOptionalFlagValue("--lock", "npm:create-next-app@latest", []string{"deno", "run", "--lock", "npm:create-next-app@latest", "main.ts"}, 4, 5); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--lock,npm:create-next-app@latest) = %v, want false", got)
		}
	})

	t.Run("tunnel consumes value only when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--tunnel", "preview", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--tunnel", "preview", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--tunnel,preview) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-t", "preview", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-t", "preview", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-t,preview) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--tunnel", "preview"}
		if got := isKnownDenoOptionalFlagValue("--tunnel", "preview", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--tunnel,preview) = %v, want false", got)
		}
	})

	t.Run("install-alias consumes value only when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "x", "--install-alias", "denox", "npm:create-vite@latest"}
		if got := isKnownDenoOptionalFlagValue("--install-alias", "denox", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--install-alias,denox) = %v, want true", got)
		}
		fields = []string{"deno", "x", "--install-alias", "denox"}
		if got := isKnownDenoOptionalFlagValue("--install-alias", "denox", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--install-alias,denox) = %v, want false", got)
		}
		if got := isKnownDenoOptionalFlagValue("--install-alias", "npm:create-vite@latest", []string{"deno", "x", "--install-alias", "npm:create-vite@latest", "main.ts"}, 4, 5); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--install-alias,npm:create-vite@latest) = %v, want false", got)
		}
	})

	t.Run("allow-import rejects invalid values", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-import", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-import", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-import,npm:create-vite) = %v, want false", got)
		}
	})

	t.Run("allow-read/net/env consume values when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-read", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-read", ".", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-read,.) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--allow-net", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-net", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-net,deno.land) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--allow-env", "PATH", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-env", "PATH", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-env,PATH) = %v, want true", got)
		}
	})

	t.Run("allow-write/run/ffi consume values when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-write", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-write", ".", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-write,.) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--allow-run", "deno", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-run", "deno", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-run,deno) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--allow-ffi", "./native.so", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-ffi", "./native.so", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-ffi,./native.so) = %v, want true", got)
		}
	})

	t.Run("allow-sys consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-sys", "hostname", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--allow-sys", "hostname", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-sys,hostname) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-S", "hostname", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-S", "hostname", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-S,hostname) = %v, want true", got)
		}
	})

	t.Run("inspect flags consume value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--inspect", "127.0.0.1:9229", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--inspect", "127.0.0.1:9229", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--inspect,127.0.0.1:9229) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--inspect-brk", "9229", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--inspect-brk", "9229", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--inspect-brk,9229) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--inspect-wait", "localhost:9229", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--inspect-wait", "localhost:9229", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--inspect-wait,localhost:9229) = %v, want true", got)
		}
	})

	t.Run("watch consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--watch", "src", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--watch", "src", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch,src) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--watch", "src"}
		if got := isKnownDenoOptionalFlagValue("--watch", "src", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch,src) = %v, want false", got)
		}
	})

	t.Run("watch-exclude consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--watch-exclude", "dist", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--watch-exclude", "dist", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch-exclude,dist) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--watch-exclude", "dist"}
		if got := isKnownDenoOptionalFlagValue("--watch-exclude", "dist", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch-exclude,dist) = %v, want false", got)
		}
	})

	t.Run("watch-hmr consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--watch-hmr", "src", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--watch-hmr", "src", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch-hmr,src) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--watch-hmr", "src"}
		if got := isKnownDenoOptionalFlagValue("--watch-hmr", "src", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--watch-hmr,src) = %v, want false", got)
		}
	})

	t.Run("coverage consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--coverage", "coverage", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--coverage", "coverage", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--coverage,coverage) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--coverage", "coverage"}
		if got := isKnownDenoOptionalFlagValue("--coverage", "coverage", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--coverage,coverage) = %v, want false", got)
		}
	})

	t.Run("no-check consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--no-check", "remote", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--no-check", "remote", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--no-check,remote) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--no-check", "remote"}
		if got := isKnownDenoOptionalFlagValue("--no-check", "remote", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--no-check,remote) = %v, want false", got)
		}
	})

	t.Run("check consumes value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--check", "all", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--check", "all", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--check,all) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--check", "all"}
		if got := isKnownDenoOptionalFlagValue("--check", "all", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--check,all) = %v, want false", got)
		}
	})

	t.Run("frozen consumes boolean value when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--frozen", "false", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--frozen", "false", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--frozen,false) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--frozen", "false"}
		if got := isKnownDenoOptionalFlagValue("--frozen", "false", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--frozen,false) = %v, want false", got)
		}
	})

	t.Run("inspect flags reject invalid values", func(t *testing.T) {
		fields := []string{"deno", "run", "--inspect", "127.0.0.1:9229", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--inspect", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--inspect,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--inspect", "127.0.0.1:9229"}
		if got := isKnownDenoOptionalFlagValue("--inspect", "127.0.0.1:9229", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--inspect,127.0.0.1:9229) = %v, want false", got)
		}
	})

	t.Run("allow-sys returns false without following target", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-sys", "hostname"}
		if got := isKnownDenoOptionalFlagValue("--allow-sys", "hostname", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-sys,hostname) = %v, want false", got)
		}
	})

	t.Run("deny permission variants consume values when candidate follows", func(t *testing.T) {
		fields := []string{"deno", "run", "--deny-read", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-read", ".", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-read,.) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-write", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-write", ".", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-write,.) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-net", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-net", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-net,deno.land) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-env", "PATH", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-env", "PATH", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-env,PATH) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-run", "deno", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-run", "deno", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-run,deno) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-ffi", "./native.so", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-ffi", "./native.so", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-ffi,./native.so) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-import", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-import", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-import,deno.land) = %v, want true", got)
		}
		fields = []string{"deno", "run", "--deny-sys", "hostname", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-sys", "hostname", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-sys,hostname) = %v, want true", got)
		}
	})

	t.Run("deny permission variants return false for invalid values", func(t *testing.T) {
		fields := []string{"deno", "run", "--deny-read", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-read", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-read,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-write", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-write", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-write,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-net", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-net", "local-path", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-net,local-path) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-env", "PATH", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-env", "1BAD", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-env,1BAD) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-run", "deno", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-run", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-run,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-ffi", "./native.so", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-ffi", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-ffi,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-import", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-import", "npm:create-vite", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-import,npm:create-vite) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--deny-sys", "hostname", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--deny-sys", "1bad", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--deny-sys,1bad) = %v, want false", got)
		}
	})

	t.Run("deny permission variants return false without following target", func(t *testing.T) {
		cases := []struct {
			flag  string
			value string
		}{
			{flag: "--deny-read", value: "."},
			{flag: "--deny-write", value: "."},
			{flag: "--deny-net", value: "deno.land"},
			{flag: "--deny-env", value: "PATH"},
			{flag: "--deny-run", value: "deno"},
			{flag: "--deny-ffi", value: "./native.so"},
			{flag: "--deny-import", value: "deno.land"},
			{flag: "--deny-sys", value: "hostname"},
		}
		for _, tc := range cases {
			fields := []string{"deno", "run", tc.flag, tc.value}
			if got := isKnownDenoOptionalFlagValue(tc.flag, tc.value, fields, 4, len(fields)); got {
				t.Fatalf("isKnownDenoOptionalFlagValue(%s,%s) = %v, want false", tc.flag, tc.value, got)
			}
		}
	})

	t.Run("allow-write/run/ffi return false without following target", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-write", "."}
		if got := isKnownDenoOptionalFlagValue("--allow-write", ".", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-write,.) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--allow-run", "deno"}
		if got := isKnownDenoOptionalFlagValue("--allow-run", "deno", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-run,deno) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--allow-ffi", "./native.so"}
		if got := isKnownDenoOptionalFlagValue("--allow-ffi", "./native.so", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-ffi,./native.so) = %v, want false", got)
		}
	})

	t.Run("allow-read/net/env return false without following target", func(t *testing.T) {
		fields := []string{"deno", "run", "--allow-read", "."}
		if got := isKnownDenoOptionalFlagValue("--allow-read", ".", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-read,.) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--allow-net", "deno.land"}
		if got := isKnownDenoOptionalFlagValue("--allow-net", "deno.land", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-net,deno.land) = %v, want false", got)
		}
		fields = []string{"deno", "run", "--allow-env", "PATH"}
		if got := isKnownDenoOptionalFlagValue("--allow-env", "PATH", fields, 4, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--allow-env,PATH) = %v, want false", got)
		}
	})

	t.Run("short permission flags are recognized distinctly from reload", func(t *testing.T) {
		fields := []string{"deno", "run", "-R", ".", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-R", ".", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-R,.) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-N", "deno.land", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-N", "deno.land", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-N,deno.land) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-E", "PATH", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-E", "PATH", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-E,PATH) = %v, want true", got)
		}
		fields = []string{"deno", "run", "-r", "npm:chalk@5", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("-r", "npm:chalk@5", fields, 4, len(fields)); !got {
			t.Fatalf("isKnownDenoOptionalFlagValue(-r,npm:chalk@5) = %v, want true", got)
		}
	})

	t.Run("rejects empty and flag-like values", func(t *testing.T) {
		fields := []string{"deno", "run", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--vendor", "", fields, 0, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--vendor,\"\") = %v, want false", got)
		}
		if got := isKnownDenoOptionalFlagValue("--vendor", "--something", fields, 0, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--vendor,--something) = %v, want false", got)
		}
	})

	t.Run("returns false for unknown optional flag key", func(t *testing.T) {
		fields := []string{"deno", "run", "main.ts"}
		if got := isKnownDenoOptionalFlagValue("--unknown-flag", "value", fields, 0, len(fields)); got {
			t.Fatalf("isKnownDenoOptionalFlagValue(--unknown-flag,value) = %v, want false", got)
		}
	})
}

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

func TestCanonicalDenoFlagToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "--ALLOW-READ", want: "--allow-read"},
		{in: "--allow-net", want: "--allow-net"},
		{in: "-R", want: "-R"},
		{in: "-r", want: "-r"},
		{in: "-W", want: "-W"},
		{in: "--ALLOW-RUN", want: "--allow-run"},
		{in: "-S", want: "-S"},
		{in: "--ALLOW-SYS", want: "--allow-sys"},
		{in: "--INSPECT-BRK", want: "--inspect-brk"},
		{in: "--V8-FLAGS", want: "--v8-flags"},
		{in: "--NO-CHECK", want: "--no-check"},
	}
	for _, tc := range cases {
		if got := canonicalDenoFlagToken(tc.in); got != tc.want {
			t.Fatalf("canonicalDenoFlagToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsDenoRequiredValueFlag(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "long config flag", in: "--config", want: true},
		{name: "short c flag", in: "-c", want: true},
		{name: "serve host flag", in: "--host", want: true},
		{name: "serve port flag", in: "--port", want: true},
		{name: "install entrypoint flag", in: "--entrypoint", want: true},
		{name: "install short entrypoint flag", in: "-e", want: true},
		{name: "install name flag", in: "--name", want: true},
		{name: "install short name flag", in: "-n", want: true},
		{name: "install root flag", in: "--root", want: true},
		{name: "short package flag", in: "-p", want: true},
		{name: "long package flag", in: "--package", want: true},
		{name: "optional reload flag", in: "--reload", want: false},
		{name: "optional frozen flag", in: "--frozen", want: false},
		{name: "unknown flag", in: "--not-a-flag", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDenoRequiredValueFlag(tc.in); got != tc.want {
				t.Fatalf("isDenoRequiredValueFlag(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsDenoOptionalValueFlag(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "reload long flag", in: "--reload", want: true},
		{name: "reload short flag", in: "-r", want: true},
		{name: "lock flag", in: "--lock", want: true},
		{name: "allow-import long flag", in: "--allow-import", want: true},
		{name: "allow-import short flag", in: "-I", want: true},
		{name: "deny-sys flag", in: "--deny-sys", want: true},
		{name: "required-value flag is not optional", in: "--config", want: false},
		{name: "unknown flag", in: "--not-a-flag", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDenoOptionalValueFlag(tc.in); got != tc.want {
				t.Fatalf("isDenoOptionalValueFlag(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDenoOptionalValueFlagCoverage(t *testing.T) {
	optionalWithoutCandidate := map[string]struct{}{
		"--vendor":           {},
		"--node-modules-dir": {},
	}

	for flag := range denoOptionalValueFlags {
		if _, ok := denoOptionalValueValidatorsRequiringCandidate[flag]; ok {
			continue
		}
		if _, ok := optionalWithoutCandidate[flag]; ok {
			continue
		}
		t.Fatalf("deno optional flag %q has no optional-value validator path", flag)
	}

	for flag := range denoOptionalValueValidatorsRequiringCandidate {
		if _, ok := denoOptionalValueFlags[flag]; !ok {
			t.Fatalf("deno optional-value validator for %q is not listed as optional flag", flag)
		}
	}
}

func TestIsDenoInstallGlobalMode(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
		start  int
		end    int
		want   bool
	}{
		{
			name:   "short global flag enables global mode",
			fields: []string{"deno", "install", "-g", "npm:create-next-app@latest"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "long global flag enables global mode",
			fields: []string{"deno", "install", "--global", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "combined short flags including g enable global mode",
			fields: []string{"deno", "install", "-gNR", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "short flag with attached value does not imply global mode",
			fields: []string{"deno", "install", "-Ngoogle.com", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   false,
		},
		{
			name:   "global true equals enables global mode",
			fields: []string{"deno", "install", "--global=true", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "global on equals enables global mode",
			fields: []string{"deno", "install", "--global=on", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "global one equals enables global mode",
			fields: []string{"deno", "install", "--global=1", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   true,
		},
		{
			name:   "global false equals does not enable global mode",
			fields: []string{"deno", "install", "--global=false", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   false,
		},
		{
			name:   "global zero equals does not enable global mode",
			fields: []string{"deno", "install", "--global=0", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   false,
		},
		{
			name:   "global off equals does not enable global mode",
			fields: []string{"deno", "install", "--global=off", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   false,
		},
		{
			name:   "invalid global equals does not enable global mode",
			fields: []string{"deno", "install", "--global=maybe", "jsr:@std/http"},
			start:  2,
			end:    4,
			want:   false,
		},
		{
			name:   "no global flag is local mode",
			fields: []string{"deno", "install", "jsr:@std/http"},
			start:  2,
			end:    3,
			want:   false,
		},
		{
			name:   "separator stops global scan",
			fields: []string{"deno", "install", "--", "-g", "jsr:@std/http"},
			start:  2,
			end:    5,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDenoInstallGlobalMode(tc.fields, tc.start, tc.end); got != tc.want {
				t.Fatalf("isDenoInstallGlobalMode(%v, %d, %d) = %v, want %v", tc.fields, tc.start, tc.end, got, tc.want)
			}
		})
	}
}

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
