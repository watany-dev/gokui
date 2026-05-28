package app

import (
	"os"
	"strings"
	"testing"
)

func TestInstallReportPolicyDecisionControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `policy_profile` / `decision` fields must not contain C0/C1"
	requiredReadmeContinuation := "control characters during lock verify and reuse/baseline integrity checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report policy/decision control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `policy_profile`/`decision` validation hardening with C0/C1 control-character rejection for lock-verify and install/update integrity checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report policy/decision control-char hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportPolicyDecisionUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `policy_profile` / `decision` fields must not contain Unicode"
	requiredReadmeContinuation := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report policy/decision unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `policy_profile`/`decision` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection for lock-verify and install/update integrity checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report policy/decision unicode hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportSourceControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `source.input` / `source.kind` fields must not contain C0/C1"
	requiredReadmeContinuation := "control characters during lock verify and reuse/baseline integrity checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report source control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `source.input`/`source.kind` validation hardening with C0/C1 control-character rejection for lock-verify and install/update integrity checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report source control-char hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportSourceCanonicalUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `source.input` / `source.kind` fields must not be empty, must"
	requiredReadmeContinuation := "not contain surrounding whitespace, and must not contain Unicode"
	requiredReadmeTail := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) || !strings.Contains(readme, requiredReadmeTail) {
		t.Fatalf("README missing install report source canonical/unicode hardening line: %q ... %q ... %q", requiredReadme, requiredReadmeContinuation, requiredReadmeTail)
	}

	requiredRoadmap := "Install report `source.input`/`source.kind` canonical validation hardening with empty/surrounding-whitespace rejection and Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report source canonical/unicode hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportInstalledPathControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `installed_path` must not contain C0/C1 control characters"
	requiredReadmeContinuation := "during lock verify and reuse/baseline integrity checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report installed_path control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `installed_path` validation hardening with C0/C1 control-character rejection for lock-verify and install/update integrity checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report installed_path control-char hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportInstalledPathCanonicalUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `installed_path` must not be empty, must not contain"
	requiredReadmeContinuation := "surrounding whitespace, and must not contain Unicode"
	requiredReadmeTail := "bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) || !strings.Contains(readme, requiredReadmeTail) {
		t.Fatalf("README missing install report installed_path canonical/unicode hardening line: %q ... %q ... %q", requiredReadme, requiredReadmeContinuation, requiredReadmeTail)
	}

	requiredRoadmap := "Install report `installed_path` canonical validation hardening with empty/surrounding-whitespace rejection and Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report installed_path canonical/unicode hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportSchemaVersionControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `schema_version` must not contain C0/C1 control characters"
	requiredReadmeContinuation := "during lock verify and reuse/baseline integrity checks."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report schema_version control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `schema_version` validation hardening with C0/C1 control-character rejection for lock-verify and install/update integrity checks"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report schema_version control-char hardening line: %q", requiredRoadmap)
	}
}

func TestInstallReportSchemaVersionCanonicalUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Install report `schema_version` must not contain surrounding whitespace and"
	requiredReadmeContinuation := "must not contain Unicode bidi/zero-width/tag/variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing install report schema_version canonical/unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Install report `schema_version` canonical validation hardening with surrounding-whitespace rejection and Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing install report schema_version canonical/unicode hardening line: %q", requiredRoadmap)
	}
}
