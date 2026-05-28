package app

import (
	"os"
	"strings"
	"testing"
)

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
