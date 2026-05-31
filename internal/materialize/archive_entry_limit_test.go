package materialize

import "testing"

func TestArchiveEntryMaxWriteCapsDeclaredSize(t *testing.T) {
	got, err := archiveEntryMaxWrite(1, 100, 50)
	if err != nil {
		t.Fatalf("archiveEntryMaxWrite() error = %v", err)
	}
	if got != 1 {
		t.Fatalf("archiveEntryMaxWrite() = %d, want 1", got)
	}
}

func TestValidateExtractedEntrySizeRejectsMismatch(t *testing.T) {
	err := validateExtractedEntrySize("skill/evil.txt", 20, 5)
	if err == nil {
		t.Fatal("expected size mismatch error")
	}
}
