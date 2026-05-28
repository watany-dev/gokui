package app

import (
	"os"
	"strings"
	"testing"
)

func TestSourceMetadataControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `schema`/`source_kind`/`resolved_ref`/`fetched_at`/"
	requiredReadmeContinuation := "`skill_root_sha256` fields must not contain C0/C1 control characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing source-metadata control-char hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Source metadata `schema`/`source_kind`/`resolved_ref`/`fetched_at`/`skill_root_sha256` validation hardening with C0/C1 control-character rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata control-char hardening line: %q", requiredRoadmap)
	}
}

func TestSourceMetadataSourceInputControlCharHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `source_input` must also not contain C0/C1 control characters."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing source-metadata source_input control-char hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Source metadata `source_input` validation hardening with C0/C1 control-character rejection at metadata verification layer"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata source_input control-char hardening line: %q", requiredRoadmap)
	}
}

func TestSourceMetadataSourceInputUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `source_input` must not contain Unicode bidi/zero-width/tag/"
	requiredReadmeContinuation := "variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing source-metadata source_input unicode hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Source metadata `source_input` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection at metadata verification layer"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata source_input unicode hardening line: %q", requiredRoadmap)
	}
}

func TestSourceMetadataSchemaCanonicalDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `schema` must not contain leading/trailing whitespace."
	if !strings.Contains(readme, requiredReadme) {
		t.Fatalf("README missing source-metadata schema canonical hardening line: %q", requiredReadme)
	}

	requiredRoadmap := "Source metadata `schema` canonical validation hardening with explicit surrounding-whitespace rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata schema canonical hardening line: %q", requiredRoadmap)
	}
}

func TestSourceMetadataSourceKindFetchedAtCanonicalDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `source_kind` and `fetched_at` must be canonical without"
	requiredReadmeContinuation := "leading/trailing whitespace (`source_kind` also requires lowercase)."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) {
		t.Fatalf("README missing source-metadata source_kind/fetched_at canonical hardening line: %q ... %q", requiredReadme, requiredReadmeContinuation)
	}

	requiredRoadmap := "Source metadata `source_kind`/`fetched_at` canonical validation hardening with explicit surrounding-whitespace rejection (and lowercase canonicalization for `source_kind`)"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata source_kind/fetched_at canonical hardening line: %q", requiredRoadmap)
	}
}

func TestSourceMetadataUnicodeHardeningDocumentationSync(t *testing.T) {
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

	requiredReadme := "Source metadata `schema`/`source_kind`/`resolved_ref`/`fetched_at`/"
	requiredReadmeContinuation := "`skill_root_sha256` must not contain Unicode bidi/zero-width/tag/"
	requiredReadmeTail := "variation-selector characters."
	if !strings.Contains(readme, requiredReadme) || !strings.Contains(readme, requiredReadmeContinuation) || !strings.Contains(readme, requiredReadmeTail) {
		t.Fatalf("README missing source-metadata unicode hardening line: %q ... %q ... %q", requiredReadme, requiredReadmeContinuation, requiredReadmeTail)
	}

	requiredRoadmap := "Source metadata `schema`/`source_kind`/`resolved_ref`/`fetched_at`/`skill_root_sha256` validation hardening with Unicode bidi/zero-width/tag/variation-selector rejection"
	if !strings.Contains(roadmap, requiredRoadmap) {
		t.Fatalf("ROADMAP missing source-metadata unicode hardening line: %q", requiredRoadmap)
	}
}
