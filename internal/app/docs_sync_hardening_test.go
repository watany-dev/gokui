package app

import (
	"os"
	"strings"
	"testing"
)

func TestVetFailClosedInspectPayloadDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "`vet` also fail-closes (`REJECTED`) when embedded inspect JSON payloads are malformed or non-UTF-8."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing vet fail-closed payload hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "vet fail-closed decision hardening for malformed/non-UTF-8 embedded inspect JSON payloads"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing vet fail-closed payload hardening line: %q", requiredRoadmap)
	}
}

func TestScanNonUTF8TextHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Scan text targets (`markdown`/`script`/`manifest`) now fail-closed with a high-severity finding when file payloads are non-UTF-8."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing scan non-utf8 hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "high-severity fail-closed detection for non-UTF-8 payloads in markdown/script/manifest scan targets"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing scan non-utf8 hardening line: %q", requiredRoadmap)
	}
}

func TestUpdateURLScanUTF8HardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Update URL scan also rejects non-UTF-8 markdown payloads before URL extraction."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing update URL scan utf-8 hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Update URL scan read-path hardening with non-UTF-8 markdown payload rejection before URL extraction"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing update URL scan utf-8 hardening line: %q", requiredRoadmap)
	}
}

func TestPolicyUTF8HardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Policy files (`policy.toml` / `.gokui-policy.toml`) must be valid UTF-8."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing policy utf-8 hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Policy file load-path hardening with invalid UTF-8 rejection for `policy.toml` / `.gokui-policy.toml`"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing policy utf-8 hardening line: %q", requiredRoadmap)
	}
}

func TestLockPathUTF8HardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock skill file paths in `gokui.lock` must be valid UTF-8 and must not contain"
	requiredReadmeContinuation := "C0/C1 control characters for install/update/lock verify provenance checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock path utf-8/control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}
	requiredRoadmap := "Lock skill file-path validation hardening with invalid UTF-8 and C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock path utf-8/control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockPathWhitespaceHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock skill file paths in `gokui.lock` must not contain leading or trailing"
	requiredReadmeContinuation := "whitespace."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock path whitespace hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}
	requiredRoadmap := "Lock skill file-path canonical validation hardening with surrounding-whitespace rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock path whitespace hardening line: %q", requiredRoadmap)
	}
}

func TestLockPathUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock skill file paths in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock path unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}
	requiredRoadmap := "Lock skill file-path validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock path unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockSourceInputControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock source inputs in `gokui.lock` must not contain C0/C1 control characters"
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing lock source input control-char hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Lock source-input validation hardening with C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock source input control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockSourceInputUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock source inputs in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock source input unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock source-input validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock source input unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockNameControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock names in `gokui.lock` must not contain C0/C1 control characters for"
	requiredReadmeContinuation := "install/update/lock verify provenance checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock name control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock name validation hardening with C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock name control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockNameUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock names in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock name unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock name validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock name unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockSourceKindTypeControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock source kind/type fields in `gokui.lock` must not contain C0/C1 control"
	requiredReadmeContinuation := "characters for install/update/lock verify provenance checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock source kind/type control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock source kind/type validation hardening with C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock source kind/type control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockSourceKindTypeUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock source kind/type fields in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock source kind/type unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock source kind/type validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock source kind/type unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockPolicyProfileDecisionControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock policy profile/decision fields in `gokui.lock` must not contain C0/C1"
	requiredReadmeContinuation := "control characters for install/update/lock verify provenance checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock policy profile/decision control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock policy profile/decision validation hardening with C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock policy profile/decision control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockPolicyDecisionWhitespaceHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock policy decision in `gokui.lock` must not contain leading or trailing"
	requiredReadmeContinuation := "whitespace."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock policy decision whitespace hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock policy decision canonical validation hardening with surrounding-whitespace rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock policy decision whitespace hardening line: %q", requiredRoadmap)
	}
}

func TestLockPolicyProfileDecisionUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock policy profile/decision fields in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock policy profile/decision unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock policy profile/decision validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock policy profile/decision unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockInstalledAtControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock `installed_at` in `gokui.lock` must not contain C0/C1 control characters"
	requiredReadmeContinuation := "for install/update/lock verify provenance checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock installed_at control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock `installed_at` validation hardening with C0/C1 control-character rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock installed_at control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockInstalledAtUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock `installed_at` in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock installed_at unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock `installed_at` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update/lock-verify provenance checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock installed_at unicode hardening line: %q", requiredRoadmap)
	}
}

func TestLockSchemaControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock `schema` in `gokui.lock` must not contain C0/C1 control characters for"
	requiredReadmeContinuation := "install/update validation and lock verify schema checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock schema control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock `schema` validation hardening with C0/C1 control-character rejection for install/update and lock-verify schema checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock schema control-char hardening line: %q", requiredRoadmap)
	}
}

func TestLockSchemaWhitespaceHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock `schema` in `gokui.lock` must not contain leading or trailing whitespace."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing lock schema whitespace hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Lock `schema` canonical validation hardening with surrounding-whitespace rejection for install/update and lock-verify schema checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock schema whitespace hardening line: %q", requiredRoadmap)
	}
}

func TestLockSchemaUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock `schema` in `gokui.lock` must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing lock schema unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock `schema` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for install/update and lock-verify schema checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing lock schema unicode hardening line: %q", requiredRoadmap)
	}
}

func TestSeverityOverridesControlCharHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock/install report `severity_overrides` entries must not contain C0/C1"
	requiredReadmeContinuation := "control characters in audit string fields."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing severity_overrides control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock/install-report `severity_overrides` audit-entry validation hardening with C0/C1 control-character rejection across string fields"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing severity_overrides control-char hardening line: %q", requiredRoadmap)
	}
}

func TestSeverityOverridesDuplicateRuleIDHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock/install report `severity_overrides` entries must not contain duplicate"
	requiredReadmeContinuation := "`rule_id` values."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing severity_overrides duplicate-rule_id hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock/install-report `severity_overrides` validation hardening with duplicate `rule_id` rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing severity_overrides duplicate-rule_id hardening line: %q", requiredRoadmap)
	}
}

func TestSeverityOverridesApproverJustificationWhitespaceHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock/install report `severity_overrides` `justification`/`approved_by` fields"
	requiredReadmeContinuation := "must not contain leading or trailing whitespace."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing severity_overrides approver/justification whitespace hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock/install-report `severity_overrides` `justification`/`approved_by` validation hardening with surrounding-whitespace rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing severity_overrides approver/justification whitespace hardening line: %q", requiredRoadmap)
	}
}

func TestSeverityOverridesApproverJustificationUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock/install report `severity_overrides` `justification`/`approved_by` fields"
	requiredReadmeContinuation := "must not contain Unicode bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing severity_overrides approver/justification unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Lock/install-report `severity_overrides` `justification`/`approved_by` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing severity_overrides approver/justification unicode hardening line: %q", requiredRoadmap)
	}
}

func TestSeverityOverridesCoreFieldsUnicodeHardeningDocumentationSync(t *testing.T) {
	readmeBytes, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("failed to read README.md: %v", err)
	}
	readme := string(readmeBytes)
	roadmapBytes, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read ROADMAP.md: %v", err)
	}
	roadmap := string(roadmapBytes)

	requiredReadme := "Lock/install report `severity_overrides` `rule_id`/`previous_severity`/"
	requiredReadmeContinuation := "`effective_severity`/`source`/`applied_at` fields must not contain Unicode"
	requiredReadmeTail := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) || !strings.Contains(readme, requiredReadmeTail) {
		t.Fatalf("README missing severity_overrides core-fields unicode hardening line: %q ... %q ... %q", requiredReadme, requiredReadmeContinuation, requiredReadmeTail)
	}

	requiredRoadmap := "Lock/install-report `severity_overrides` `rule_id`/`previous_severity`/`effective_severity`/`source`/`applied_at` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing severity_overrides core-fields unicode hardening line: %q", requiredRoadmap)
	}
}
