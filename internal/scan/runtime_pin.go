package scan

import "strings"

func isUnpinnedRuntimeToolLine(line string) bool {
	trimmedLine := strings.TrimSpace(line)
	lowerLine := strings.ToLower(trimmedLine)
	if isRemoteScriptImportLine(lowerLine) {
		return true
	}
	if isUnpinnedDenoNpmRuntimeLine(trimmedLine) {
		return true
	}

	fields := strings.Fields(trimmedLine)
	if len(fields) == 0 {
		return false
	}

	for i := 0; i < len(fields); i++ {
		token := normalizeLauncherToken(fields[i])
		if token == "" {
			continue
		}
		suffixFields := normalizedRuntimeSuffixFields(fields, i, token)
		if token == "deno" {
			if isUnpinnedDenoNpmRuntimeLine(strings.Join(suffixFields, " ")) {
				return true
			}
			if isRemoteDenoRuntimeLine(strings.Join(suffixFields, " ")) {
				return true
			}
			continue
		}
		if token == "corepack" {
			launcher, launcherIndex, ok := nextNonFlagFieldWithIndex(suffixFields, 1)
			if !ok {
				continue
			}
			launcher = normalizeLauncherToken(launcher)
			if (launcher == "dlx" || launcher == "exec") && launcherIndex >= 0 && launcherIndex < len(suffixFields) {
				// Handle compact shell-separated forms like `corepack pnpm;dlx ...`
				// where package manager and subcommand are glued in the same field.
				if pm, subcommand, hasComposite := splitCompositeRuntimeToken(suffixFields[launcherIndex]); hasComposite {
					pm = normalizeLauncherToken(pm)
					if (pm == "pnpm" || pm == "yarn" || pm == "npm") && subcommand == launcher {
						normalized := make([]string, 0, len(suffixFields)+1)
						normalized = append(normalized, suffixFields[:launcherIndex]...)
						normalized = append(normalized, pm, launcher)
						normalized = append(normalized, suffixFields[launcherIndex+1:]...)
						suffixFields = normalized
						launcher = pm
					}
				}
			}
			if isUnpinnedLauncherCommand(suffixFields, launcher, launcherIndex) {
				return true
			}
			continue
		}

		if isUnpinnedLauncherCommand(suffixFields, token, 0) {
			return true
		}
	}

	return false
}

func normalizeLauncherToken(token string) string {
	token = strings.TrimSpace(strings.ToLower(sanitizeRuntimeToken(token)))
	if token == "" {
		return token
	}
	if idx := strings.LastIndexAny(token, ";|&!"); idx >= 0 && idx+1 < len(token) {
		tail := strings.TrimSpace(token[idx+1:])
		if tail != "" {
			token = strings.ToLower(sanitizeRuntimeToken(tail))
		}
	}
	for _, launcher := range []string{"npx", "uvx", "bunx", "pnpm", "yarn", "npm"} {
		prefix := launcher + "@"
		if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
			return launcher
		}
	}
	return token
}

func normalizedRuntimeSuffixFields(fields []string, start int, first string) []string {
	if start < 0 || start >= len(fields) {
		return nil
	}
	out := make([]string, 0, len(fields)-start)
	out = append(out, first)
	if start+1 < len(fields) {
		out = append(out, fields[start+1:]...)
	}
	return out
}

func splitCompositeRuntimeToken(raw string) (string, string, bool) {
	token := strings.TrimSpace(sanitizeRuntimeToken(raw))
	if token == "" {
		return "", "", false
	}
	idx := strings.LastIndexAny(token, ";|&!")
	if idx <= 0 || idx+1 >= len(token) {
		return "", "", false
	}
	left := strings.TrimSpace(sanitizeRuntimeToken(token[:idx]))
	right := normalizeLauncherToken(token[idx+1:])
	if left == "" || right == "" {
		return "", "", false
	}
	return left, right, true
}

func sanitizeRuntimeToken(token string) string {
	for {
		prev := token
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, "$(") && len(token) > 2 {
			token = strings.TrimSpace(token[2:])
		}

		// Normalize backslash-escaped quote wrappers used in markdown/json
		// snippets, e.g. \"deno\" -> deno.
		if len(token) >= 4 {
			switch {
			case strings.HasPrefix(token, "\\\"") && strings.HasSuffix(token, "\\\""):
				token = token[2 : len(token)-2]
			case strings.HasPrefix(token, "\\'") && strings.HasSuffix(token, "\\'"):
				token = token[2 : len(token)-2]
			case strings.HasPrefix(token, "\\`") && strings.HasSuffix(token, "\\`"):
				token = token[2 : len(token)-2]
			}
		}
		token = strings.Trim(token, "\"'`,;:()[]{}&|!")
		if token == prev {
			break
		}
	}
	return token
}

func isUnpinnedLauncherCommand(fields []string, token string, tokenIndex int) bool {
	switch token {
	case "npx", "uvx", "bunx":
		packageRefs := extractPackageRefsFromFlags(fields, tokenIndex+1, len(fields))
		if len(packageRefs) > 0 {
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}
		packageRef, ok := nextRuntimePackageCandidate(fields, tokenIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "pnpm", "yarn":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || !strings.EqualFold(subcommand, "dlx") {
			return false
		}

		packageRefs := extractPackageRefsFromFlags(fields, subcommandIndex+1, len(fields))
		if len(packageRefs) > 0 {
			if postSepRef, ok := nextExplicitPackageLikeTokenAfterSeparator(fields, subcommandIndex+1, len(fields)); ok {
				packageRefs = append(packageRefs, postSepRef)
			}
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}

		packageRef, ok := nextRuntimePackageCandidate(fields, subcommandIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "npm":
		subcommand, subcommandIndex, ok := nextNonFlagFieldWithIndex(fields, tokenIndex+1)
		if !ok || !strings.EqualFold(subcommand, "exec") {
			return false
		}

		packageRefs := extractPackageRefsFromFlags(fields, subcommandIndex+1, len(fields))
		if len(packageRefs) > 0 {
			if postSepRef, ok := nextExplicitPackageLikeTokenAfterSeparator(fields, subcommandIndex+1, len(fields)); ok {
				packageRefs = append(packageRefs, postSepRef)
			}
			for _, packageRef := range packageRefs {
				if isUnpinnedPackageRef(packageRef) {
					return true
				}
			}
			return false
		}

		packageRef, ok := nextRuntimePackageCandidate(fields, subcommandIndex+1, len(fields))
		if !ok {
			return false
		}
		packageRef = sanitizeRuntimeToken(packageRef)
		return isUnpinnedPackageRef(packageRef)
	case "go":
		runArgsStart, ok := findGoRunArgsStart(fields, tokenIndex)
		if !ok {
			return false
		}
		target, ok := nextGoRunTarget(fields, runArgsStart, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedGoRunTarget(target)
	default:
		return false
	}
}

func isUnpinnedGoRunTarget(target string) bool {
	if target == "" {
		return false
	}
	if strings.HasSuffix(target, ".go") {
		return false
	}
	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "/") {
		return false
	}
	if strings.HasPrefix(target, ".\\") || strings.HasPrefix(target, "..\\") || strings.HasPrefix(target, "\\") {
		return false
	}

	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		if len(parts) != 2 {
			return false
		}
		version := strings.TrimSpace(parts[1])
		return !isPinnedGoModuleVersion(version)
	}

	// Remote Go module/package paths conventionally include a dot in the first segment.
	firstSegment := target
	if slash := strings.Index(firstSegment, "/"); slash >= 0 {
		firstSegment = firstSegment[:slash]
	}
	return strings.Contains(firstSegment, ".")
}

func isPinnedGoModuleVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	if goSemverExactPattern.MatchString(lower) {
		return true
	}
	if goPseudoVersionPattern.MatchString(lower) {
		return true
	}
	if hexCommitRefPattern.MatchString(lower) {
		return true
	}
	return false
}

func isRemoteScriptImportLine(lowerLine string) bool {
	if remoteScriptImportPattern.MatchString(lowerLine) {
		return true
	}
	if remoteScriptDotImport.MatchString(lowerLine) {
		return true
	}
	return isRemoteDenoRuntimeLine(lowerLine)
}

func isRemoteDenoRuntimeLine(runtimeLine string) bool {
	fields := strings.Fields(runtimeLine)
	if len(fields) < 2 || !strings.EqualFold(sanitizeRuntimeToken(fields[0]), "deno") {
		return false
	}

	subcommand := strings.ToLower(sanitizeRuntimeToken(fields[1]))
	start := 1
	switch subcommand {
	case "run", "x", "serve":
		start = 2
	case "install":
		if !isDenoInstallGlobalMode(fields, 2, len(fields)) {
			return false
		}
		start = 2
	}

	target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
	if !ok {
		return false
	}

	lowerTarget := strings.ToLower(strings.TrimSpace(sanitizeRuntimeToken(target)))
	return strings.HasPrefix(lowerTarget, "https://") || strings.HasPrefix(lowerTarget, "http://")
}

func isUnpinnedPackageRef(ref string) bool {
	if ref == "" {
		return false
	}

	if strings.HasPrefix(ref, "@") {
		lastAt := strings.LastIndex(ref, "@")
		if lastAt <= 0 || lastAt == len(ref)-1 {
			return true
		}
		return !isPinnedPackageVersion(ref[lastAt+1:])
	}

	parts := strings.SplitN(ref, "@", 2)
	if len(parts) == 1 {
		return true
	}
	return !isPinnedPackageVersion(parts[1])
}

func isPinnedPackageVersion(version string) bool {
	if version == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(version))
	if lower == "latest" {
		return false
	}
	// Treat exact semver as pinned for package launchers. Dist-tags and ranges
	// like "next", "^1.2.3", or "~1.2.3" remain floating.
	return goSemverExactPattern.MatchString(lower)
}

func isUnpinnedDenoNpmRuntimeLine(runtimeLine string) bool {
	fields := strings.Fields(runtimeLine)
	if len(fields) < 2 || !strings.EqualFold(sanitizeRuntimeToken(fields[0]), "deno") {
		return false
	}

	subcommand := strings.ToLower(sanitizeRuntimeToken(fields[1]))
	if subcommand == "create" {
		return isUnpinnedDenoCreateRuntimeLine(fields, 2, len(fields))
	}
	if subcommand == "init" {
		return isUnpinnedDenoInitRuntimeLine(fields, 2, len(fields))
	}
	if subcommand == "serve" {
		start := 2
		target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedDenoRuntimeSpecifier(target)
	}
	if subcommand == "install" {
		if !isDenoInstallGlobalMode(fields, 2, len(fields)) {
			return false
		}
		start := 2
		target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedDenoRuntimeSpecifier(target)
	}

	start := 1
	switch subcommand {
	case "run", "x":
		start = 2
	}

	packageRefs := extractDenoNpmPackageRefs(fields, start, len(fields))
	if len(packageRefs) > 0 {
		for _, packageRef := range packageRefs {
			if isUnpinnedDenoRuntimeSpecifier(packageRef) {
				return true
			}
		}
		// When --package is present, still evaluate target specifiers.
		target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
		if !ok {
			return false
		}
		return isUnpinnedDenoRuntimeSpecifier(target)
	}

	target, ok := nextDenoRuntimeTarget(fields, start, len(fields))
	if !ok {
		return false
	}
	return isUnpinnedDenoRuntimeSpecifier(target)
}

func isUnpinnedDenoCreateRuntimeLine(fields []string, start int, end int) bool {
	packageRef, packageMode, ok := nextDenoCreatePackage(fields, start, end)
	if !ok {
		return false
	}
	return isUnpinnedDenoCreatePackageRef(packageRef, packageMode)
}

func isUnpinnedDenoInitRuntimeLine(fields []string, start int, end int) bool {
	packageRef, packageMode, ok := nextDenoCreatePackage(fields, start, end)
	if !ok {
		return false
	}
	if packageMode == "auto" &&
		!strings.HasPrefix(packageRef, "npm:") &&
		!strings.HasPrefix(packageRef, "jsr:") {
		// In auto mode, unprefixed `deno init` args are typically directories.
		return false
	}
	return isUnpinnedDenoCreatePackageRef(packageRef, packageMode)
}

func nextDenoCreatePackage(fields []string, start int, end int) (string, string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", "auto", false
	}

	packageMode := "auto"
	for i := start; i < end; i++ {
		token := sanitizeRuntimeToken(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			return "", packageMode, false
		}
		if strings.HasPrefix(token, "-") {
			switch canonicalDenoFlagToken(token) {
			case "--npm":
				packageMode = "npm"
			case "--jsr":
				packageMode = "jsr"
			}
			continue
		}
		return sanitizeRuntimeToken(token), packageMode, true
	}
	return "", packageMode, false
}

func isUnpinnedDenoCreatePackageRef(packageRef string, packageMode string) bool {
	packageRef = sanitizeRuntimeToken(strings.TrimSpace(packageRef))
	if packageRef == "" {
		return false
	}

	if strings.HasPrefix(packageRef, "npm:") || strings.HasPrefix(packageRef, "jsr:") {
		return isUnpinnedDenoRuntimeSpecifier(packageRef)
	}

	switch packageMode {
	case "npm":
		return isUnpinnedPackageRef(packageRef)
	case "jsr":
		if strings.HasPrefix(packageRef, "@") {
			return isUnpinnedDenoJSRSpecifier("jsr:" + packageRef)
		}
		// For --jsr mode, keep unprefixed package identifiers conservative.
		return true
	default:
		return false
	}
}

func extractDenoNpmPackageRefs(fields []string, start int, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return nil
	}

	out := make([]string, 0, 2)
	for i := start; i < end; i++ {
		rawToken := sanitizeRuntimeToken(fields[i])
		token := strings.ToLower(rawToken)
		switch {
		case token == "--package" || token == "-p":
			if i+1 >= end {
				continue
			}
			next := sanitizeRuntimeToken(fields[i+1])
			if next == "" || strings.HasPrefix(next, "-") {
				continue
			}
			out = append(out, next)
			i++
		case strings.HasPrefix(token, "--package="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "--package="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "-p="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p"):
			// Support attached short-form package refs like `-pnpm:create-vite`.
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "-p"))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		}
	}
	return out
}

func nextDenoRuntimeTarget(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	for i := start; i < end; i++ {
		token := sanitizeRuntimeToken(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			flagKey := canonicalDenoFlagToken(token)
			if isDenoRequiredValueFlag(flagKey) {
				i++
				continue
			}
			if isDenoOptionalValueFlag(flagKey) && i+1 < end {
				next := strings.ToLower(sanitizeRuntimeToken(fields[i+1]))
				if isKnownDenoOptionalFlagValue(flagKey, next, fields, i+2, end) {
					i++
				}
			}
			continue
		}
		return token, true
	}
	return "", false
}

func isKnownDenoOptionalFlagValue(
	flag string,
	value string,
	fields []string,
	nextStart int,
	end int,
) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	if validator, ok := denoOptionalValueValidatorsRequiringCandidate[flag]; ok {
		// Consume split optional values only when another runtime candidate
		// follows, so omitted-value forms cannot hide specifier targets.
		if !hasDenoRuntimeCandidateAfter(fields, nextStart, end) {
			return false
		}
		return validator(value)
	}

	switch flag {
	case "--vendor":
		return value == "true" || value == "false"
	case "--node-modules-dir":
		switch value {
		case "auto", "manual", "none", "true", "false":
			return true
		}
	}
	return false
}

func isDenoReloadValue(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if !isDenoReloadBlocklistValue(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func isDenoFrozenValue(value string) bool {
	return value == "true" || value == "false"
}

func isDenoReloadBlocklistValue(value string) bool {
	if value == "" {
		return false
	}
	switch {
	case strings.HasPrefix(value, "npm:"):
		return true
	case strings.HasPrefix(value, "jsr:"):
		return true
	case strings.HasPrefix(value, "http://"), strings.HasPrefix(value, "https://"):
		return true
	case strings.HasPrefix(value, "file:"):
		return true
	case strings.HasPrefix(value, "./"), strings.HasPrefix(value, "../"), strings.HasPrefix(value, "/"):
		return true
	default:
		return false
	}
}

func isDenoInspectValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if isNumericToken(value) {
		return true
	}
	if isHostLikeToken(value) {
		return true
	}
	if strings.HasPrefix(lower, "localhost:") {
		return isNumericToken(strings.TrimPrefix(lower, "localhost:"))
	}
	return false
}

func isDenoCoverageValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
	}
	return true
}

func isDenoCheckValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(value), "all")
}

func isDenoNoCheckValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
	}
	return true
}

func isDenoEnvFileValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	return true
}

func isDenoInstallAliasValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if strings.Contains(value, "/") || strings.Contains(value, "\\") ||
		strings.Contains(value, ":") || strings.Contains(value, "@") {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

func isDenoTunnelValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	return true
}

func isDenoLockValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	return true
}

func isDenoWatchValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
	}
	return true
}

func isNumericToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}

func isDenoAllowScriptsValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		// Keep allow-scripts split-value handling conservative: skip ambiguous
		// runtime specifier and path-like forms.
		if strings.Contains(token, ":") {
			return false
		}
		if strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../") ||
			strings.HasPrefix(token, "/") || strings.HasPrefix(token, ".\\") ||
			strings.HasPrefix(token, "..\\") || strings.HasPrefix(token, "\\") {
			return false
		}
		if !isScopedOrPackageRefToken(token) {
			return false
		}
	}
	return true
}

func isDenoAllowImportValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		if strings.HasPrefix(token, "https://") || strings.HasPrefix(token, "http://") {
			continue
		}
		if isHostLikeToken(token) {
			continue
		}
		return false
	}
	return true
}

func isDenoAllowReadValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") {
			return false
		}
	}
	return true
}

func isDenoAllowNetValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		if isHostLikeToken(token) {
			continue
		}
		return false
	}
	return true
}

func isDenoAllowEnvValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			return false
		}
		if token == "*" {
			continue
		}
		if !isEnvVarToken(token) {
			return false
		}
	}
	return true
}

func isDenoAllowWriteValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}

	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") {
			return false
		}
	}
	return true
}

func isDenoAllowRunValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") {
			return false
		}
	}
	return true
}

func isDenoAllowFFIValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" || strings.HasPrefix(token, "-") {
			return false
		}
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "npm:") || strings.HasPrefix(lower, "jsr:") {
			return false
		}
	}
	return true
}

func isDenoAllowSysValue(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, part := range strings.Split(value, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			return false
		}
		if token == "*" {
			continue
		}
		if !isSysApiToken(token) {
			return false
		}
	}
	return true
}

func isSysApiToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		ch := token[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
			if i == 0 {
				return false
			}
		case ch == '_':
		default:
			return false
		}
	}
	return true
}

func isEnvVarToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		ch := token[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
			if i == 0 {
				return false
			}
		case ch == '_':
		default:
			return false
		}
	}
	return true
}

func isHostLikeToken(token string) bool {
	host := token
	if strings.HasPrefix(host, "[") {
		// IPv6 host forms for allowlist values.
		endBracket := strings.Index(host, "]")
		if endBracket < 0 {
			return false
		}
		if endBracket+1 < len(host) {
			if host[endBracket+1] != ':' {
				return false
			}
			if endBracket+2 >= len(host) {
				return false
			}
		}
		return true
	}
	host = strings.TrimPrefix(host, "*.")
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		if idx == len(host)-1 {
			return false
		}
		for i := idx + 1; i < len(host); i++ {
			if host[i] < '0' || host[i] > '9' {
				return false
			}
		}
		host = host[:idx]
	}
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	for i := 0; i < len(host); i++ {
		ch := host[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '.', ch == '-':
		default:
			return false
		}
	}
	return true
}

func isScopedOrPackageRefToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		ch := token[i]
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '@', ch == '/', ch == '.', ch == '-', ch == '_':
		default:
			return false
		}
	}
	return true
}

func hasDenoRuntimeCandidateAfter(fields []string, start int, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return false
	}

	for i := start; i < end; i++ {
		token := sanitizeRuntimeToken(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return true
			}
			return false
		}
		if strings.HasPrefix(token, "-") {
			if strings.Contains(token, "=") {
				continue
			}
			flagKey := canonicalDenoFlagToken(token)
			if isDenoRequiredValueFlag(flagKey) {
				i++
			}
			continue
		}
		return true
	}
	return false
}

func canonicalDenoFlagToken(token string) string {
	if strings.HasPrefix(token, "--") {
		return strings.ToLower(token)
	}
	return token
}

func isDenoRequiredValueFlag(flagToken string) bool {
	_, ok := denoRequiredValueFlags[flagToken]
	return ok
}

func isDenoOptionalValueFlag(flagToken string) bool {
	_, ok := denoOptionalValueFlags[flagToken]
	return ok
}

func isUnpinnedDenoNpmSpecifier(ref string) bool {
	ref = strings.TrimSpace(sanitizeRuntimeToken(ref))
	if !strings.HasPrefix(ref, "npm:") {
		return false
	}
	spec := strings.TrimPrefix(ref, "npm:")
	if spec == "" {
		return false
	}
	if strings.HasPrefix(spec, "@") {
		scopeSlash := strings.Index(spec, "/")
		if scopeSlash < 0 {
			return true
		}
		lastAt := strings.LastIndex(spec, "@")
		if lastAt <= scopeSlash || lastAt == len(spec)-1 {
			return true
		}
		version := spec[lastAt+1:]
		if slash := strings.Index(version, "/"); slash >= 0 {
			version = version[:slash]
		}
		if version == "" {
			return true
		}
		return !isPinnedPackageVersion(version)
	}

	at := strings.Index(spec, "@")
	if at < 0 {
		return true
	}
	version := spec[at+1:]
	if slash := strings.Index(version, "/"); slash >= 0 {
		version = version[:slash]
	}
	if version == "" {
		return true
	}
	return !isPinnedPackageVersion(version)
}

func isUnpinnedDenoRuntimeSpecifier(ref string) bool {
	return isUnpinnedDenoNpmSpecifier(ref) || isUnpinnedDenoJSRSpecifier(ref)
}

func isUnpinnedDenoJSRSpecifier(ref string) bool {
	ref = strings.TrimSpace(sanitizeRuntimeToken(ref))
	if !strings.HasPrefix(ref, "jsr:") {
		return false
	}
	spec := strings.TrimPrefix(ref, "jsr:")
	if spec == "" {
		return false
	}

	if strings.HasPrefix(spec, "@") {
		scopeSlash := strings.Index(spec, "/")
		if scopeSlash < 0 {
			return true
		}
		lastAt := strings.LastIndex(spec, "@")
		if lastAt <= scopeSlash || lastAt == len(spec)-1 {
			return true
		}
		version := spec[lastAt+1:]
		if slash := strings.Index(version, "/"); slash >= 0 {
			version = version[:slash]
		}
		if version == "" {
			return true
		}
		return !isPinnedPackageVersion(version)
	}

	at := strings.Index(spec, "@")
	if at < 0 {
		return true
	}
	version := spec[at+1:]
	if slash := strings.Index(version, "/"); slash >= 0 {
		version = version[:slash]
	}
	if version == "" {
		return true
	}
	return !isPinnedPackageVersion(version)
}

func isDenoInstallGlobalMode(fields []string, start int, end int) bool {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	for i := start; i < end; i++ {
		token := sanitizeRuntimeToken(fields[i])
		if token == "" {
			continue
		}
		if token == "--" {
			return false
		}
		if strings.EqualFold(token, "-g") || strings.EqualFold(token, "--global") {
			return true
		}
		if hasShortFlagInCluster(token, 'g') {
			return true
		}
		if strings.HasPrefix(strings.ToLower(token), "--global=") {
			value := token[len("--global="):]
			if parsed, ok := parseBoolLikeToken(value); ok {
				if parsed {
					return true
				}
				continue
			}
			continue
		}
	}
	return false
}

func hasShortFlagInCluster(token string, shortFlag byte) bool {
	if len(token) < 2 || token[0] != '-' || token[1] == '-' {
		return false
	}
	end := len(token)
	if eq := strings.IndexByte(token, '='); eq >= 0 {
		end = eq
	}
	if end <= 1 {
		return false
	}
	for i := 1; i < end; i++ {
		current := token[i]
		if current == shortFlag {
			return true
		}
		// For short flags that may consume attached values (for example `-Nhost`),
		// treat the remaining token bytes as that flag's value, not as a flag cluster.
		if shortFlagMayConsumeAttachedValue(current) && i < end-1 {
			break
		}
	}
	return false
}

func shortFlagMayConsumeAttachedValue(flag byte) bool {
	switch flag {
	case 'c', 'e', 'n', 'p', 'L':
		return true
	case 'r', 't', 'I', 'R', 'W', 'N', 'E', 'S':
		return true
	default:
		return false
	}
}

func parseBoolLikeToken(value string) (bool, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	switch lower {
	case "1", "true", "on", "yes":
		return true, true
	case "0", "false", "off", "no":
		return false, true
	default:
		return false, false
	}
}

func nextNonFlagFieldWithIndex(fields []string, start int) (string, int, bool) {
	for i := start; i < len(fields); i++ {
		token := sanitizeRuntimeToken(fields[i])
		if token == "" {
			continue
		}
		if strings.HasPrefix(token, "-") {
			continue
		}
		return token, i, true
	}
	return "", -1, false
}

func extractPackageRefsFromFlags(fields []string, start int, end int) []string {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return nil
	}

	out := make([]string, 0, 2)
	for i := start; i < end; i++ {
		rawToken := sanitizeRuntimeToken(fields[i])
		token := strings.ToLower(rawToken)
		switch {
		case token == "--package" || token == "-p":
			if i+1 >= end {
				continue
			}
			next := sanitizeRuntimeToken(fields[i+1])
			if next == "" || strings.HasPrefix(next, "-") {
				continue
			}
			out = append(out, next)
			i++
		case strings.HasPrefix(token, "--package="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "--package="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p="):
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "-p="))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		case strings.HasPrefix(token, "-p"):
			// Support attached short-form package refs like `-p@scope/tool`.
			ref := sanitizeRuntimeToken(strings.TrimPrefix(rawToken, "-p"))
			if ref == "" {
				continue
			}
			out = append(out, ref)
		}
	}
	return out
}

func nextRuntimePackageCandidate(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	for i := start; i < end; i++ {
		token := strings.ToLower(sanitizeRuntimeToken(fields[i]))
		if token == "" {
			continue
		}
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if token == "-c" || token == "--call" {
			return "", false
		}
		if token == "-p" || token == "--package" {
			i++
			continue
		}
		if strings.HasPrefix(token, "-c=") || strings.HasPrefix(token, "--call=") {
			return "", false
		}
		if strings.HasPrefix(token, "-c") && len(token) > 2 {
			return "", false
		}
		if strings.HasPrefix(token, "-p=") || strings.HasPrefix(token, "--package=") {
			continue
		}
		if strings.HasPrefix(token, "-") {
			continue
		}
		return fields[i], true
	}
	return "", false
}

func nextExplicitPackageLikeTokenAfterSeparator(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	for i := start; i < end; i++ {
		if strings.TrimSpace(fields[i]) != "--" {
			continue
		}
		for j := i + 1; j < end; j++ {
			candidate := sanitizeRuntimeToken(fields[j])
			if candidate == "" {
				continue
			}
			if isExplicitPackageLikeRef(candidate) {
				return candidate, true
			}
			return "", false
		}
		return "", false
	}
	return "", false
}

func isExplicitPackageLikeRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.HasPrefix(ref, "@") {
		return true
	}
	if strings.Contains(ref, "@") {
		return true
	}
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, ".\\") || strings.HasPrefix(ref, "..\\") || strings.HasPrefix(ref, "\\") {
		return false
	}
	return strings.Contains(ref, "/")
}

func findGoRunArgsStart(fields []string, tokenIndex int) (int, bool) {
	if tokenIndex < 0 || tokenIndex >= len(fields) {
		return -1, false
	}
	for i := tokenIndex + 1; i < len(fields); i++ {
		token := strings.ToLower(strings.TrimSpace(sanitizeRuntimeToken(fields[i])))
		if token == "" {
			continue
		}
		if token == "run" {
			if i+1 >= len(fields) {
				return -1, false
			}
			return i + 1, true
		}
		// `go -C <dir> run ...` is a common pre-subcommand form.
		if token == "-c" {
			i++
			continue
		}
		if strings.HasPrefix(token, "-c=") {
			continue
		}
		if strings.HasPrefix(token, "-") {
			// Unknown pre-subcommand flags are treated as non-match.
			return -1, false
		}
		// Another subcommand (`go test`, `go build`, etc.)
		return -1, false
	}
	return -1, false
}

func nextGoRunTarget(fields []string, start int, end int) (string, bool) {
	if start < 0 {
		start = 0
	}
	if end > len(fields) {
		end = len(fields)
	}
	if start >= end {
		return "", false
	}

	flagNeedsValue := map[string]struct{}{
		"-mod":      {},
		"-modfile":  {},
		"-exec":     {},
		"-overlay":  {},
		"-p":        {},
		"-tags":     {},
		"-toolexec": {},
	}

	for i := start; i < end; i++ {
		token := strings.TrimSpace(sanitizeRuntimeToken(fields[i]))
		if token == "" {
			continue
		}
		lowerToken := strings.ToLower(token)
		if token == "--" {
			for j := i + 1; j < end; j++ {
				candidate := sanitizeRuntimeToken(fields[j])
				if candidate == "" {
					continue
				}
				return candidate, true
			}
			return "", false
		}
		if strings.HasPrefix(lowerToken, "-") {
			if strings.Contains(lowerToken, "=") {
				continue
			}
			if _, needsValue := flagNeedsValue[lowerToken]; needsValue {
				i++
			}
			continue
		}
		return token, true
	}
	return "", false
}
