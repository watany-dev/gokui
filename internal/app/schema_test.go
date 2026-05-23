package app

import "testing"

func TestSchemaConstantsAreStable(t *testing.T) {
	if reportSchemaVersion != "0.1.0-draft" {
		t.Fatalf("reportSchemaVersion = %q, want %q", reportSchemaVersion, "0.1.0-draft")
	}
	if lockSchemaVersion != "gokui.lock/v1" {
		t.Fatalf("lockSchemaVersion = %q, want %q", lockSchemaVersion, "gokui.lock/v1")
	}
	if sourceMetadataSchemaVersion != "gokui.source/v1" {
		t.Fatalf("sourceMetadataSchemaVersion = %q, want %q", sourceMetadataSchemaVersion, "gokui.source/v1")
	}
}
