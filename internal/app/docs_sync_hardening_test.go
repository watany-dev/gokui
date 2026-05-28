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
