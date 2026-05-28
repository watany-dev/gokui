package report

import "sort"

const (
	SARIFVersion       = "2.1.0"
	SARIFSchema        = "https://json.schemastore.org/sarif-2.1.0.json"
	SARIFDriverName    = "gokui"
	SARIFDriverVersion = "pre-release"
)

func SARIFLevelForSeverity(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

func SARIFRuleForFinding(ruleID string, summary string) SARIFRule {
	return SARIFRule{
		ID: ruleID,
		ShortDescription: SARIFMessageContainer{
			Text: summary,
		},
	}
}

func SARIFRuleForError(ruleID string, errorCode string) SARIFRule {
	return SARIFRuleForFinding(ruleID, errorCode)
}

func SARIFResultForFinding(ruleID string, level string, message string, locations []SARIFLocation) SARIFResult {
	return SARIFResult{
		RuleID:    ruleID,
		Level:     level,
		Message:   SARIFMessageContainer{Text: message},
		Locations: locations,
	}
}

func SARIFResultForError(ruleID string, message string) SARIFResult {
	return SARIFResultForFinding(ruleID, "error", message, nil)
}

func SARIFLocationForFile(file string, line int) SARIFLocation {
	location := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: file,
			},
		},
	}
	if line > 0 {
		location.PhysicalLocation.Region = &SARIFRegion{StartLine: line}
	}
	return location
}

func SortSARIFRulesByID(rules []SARIFRule) {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})
}

func SortSARIFResultsByRuleLocationMessage(results []SARIFResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		uriI := SARIFResultLocationURI(results[i])
		uriJ := SARIFResultLocationURI(results[j])
		if uriI != uriJ {
			return uriI < uriJ
		}
		return results[i].Message.Text < results[j].Message.Text
	})
}

func SARIFResultLocationURI(result SARIFResult) string {
	if len(result.Locations) == 0 {
		return ""
	}
	return result.Locations[0].PhysicalLocation.ArtifactLocation.URI
}

type SARIFFinding struct {
	ID       string
	Severity string
	File     string
	Line     int
	Summary  string
}

func SARIFDocumentForFindings(findings []SARIFFinding, executionSuccessful bool, properties SARIFProperties) SARIFDocument {
	rules := make([]SARIFRule, 0)
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		rules = append(rules, SARIFRuleForFinding(finding.ID, finding.Summary))
	}
	SortSARIFRulesByID(rules)

	results := make([]SARIFResult, 0, len(findings))
	for _, finding := range findings {
		var locations []SARIFLocation
		if finding.File != "" {
			locations = []SARIFLocation{SARIFLocationForFile(finding.File, finding.Line)}
		}
		results = append(results, SARIFResultForFinding(finding.ID, SARIFLevelForSeverity(finding.Severity), finding.Summary, locations))
	}

	return SARIFDocumentForRun(rules, results, executionSuccessful, properties)
}

func SARIFDocumentForRun(rules []SARIFRule, results []SARIFResult, executionSuccessful bool, properties SARIFProperties) SARIFDocument {
	return SARIFDocument{
		Version: SARIFVersion,
		Schema:  SARIFSchema,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    SARIFDriverName,
						Version: SARIFDriverVersion,
						Rules:   rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{ExecutionSuccessful: executionSuccessful},
				},
				Properties: properties,
			},
		},
	}
}

func SARIFErrorDocument(ruleID string, errorCode string, message string, properties SARIFProperties) SARIFDocument {
	return SARIFDocumentForRun(
		[]SARIFRule{SARIFRuleForError(ruleID, errorCode)},
		[]SARIFResult{SARIFResultForError(ruleID, message)},
		false,
		properties,
	)
}
