package scan

import "testing"

func TestIsRejectable(t *testing.T) {
	if !IsRejectable(Finding{Severity: "critical"}) {
		t.Fatal("critical should be rejectable")
	}
	if !IsRejectable(Finding{Severity: "high"}) {
		t.Fatal("high should be rejectable")
	}
	if IsRejectable(Finding{Severity: "medium"}) {
		t.Fatal("medium should not be rejectable")
	}
}
