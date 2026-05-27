package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSARIFDocumentJSONShape(t *testing.T) {
	doc := SARIFDocument{
		Version: SARIFVersion,
		Schema:  SARIFSchema,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{Driver: SARIFDriver{
					Name:    SARIFDriverName,
					Version: SARIFDriverVersion,
					Rules: []SARIFRule{{
						ID:               "RULE_ONE",
						ShortDescription: SARIFMessageContainer{Text: "rule one"},
					}},
				}},
				Results: []SARIFResult{{
					RuleID:  "RULE_ONE",
					Level:   "error",
					Message: SARIFMessageContainer{Text: "message"},
					Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: "SKILL.md"},
						Region:           &SARIFRegion{StartLine: 3},
					}}},
				}},
				Invocations: []SARIFInvocation{{ExecutionSuccessful: false}},
				Properties: SARIFProperties{
					SchemaVersion: "1",
					PreRelease:    true,
					SourceInput:   "src",
					SourceKind:    "local-dir",
					Decision:      "REJECTED",
					Note:          "note",
				},
			},
		},
	}

	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal(SARIFDocument) error = %v", err)
	}
	encoded := string(out)
	for _, token := range []string{`"$schema"`, `"runs"`, `"ruleId"`, `"shortDescription"`, `"executionSuccessful"`, `"schema_version"`} {
		if !strings.Contains(encoded, token) {
			t.Fatalf("encoded SARIF should contain %s, got %s", token, encoded)
		}
	}
}
