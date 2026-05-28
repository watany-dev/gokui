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

func SARIFRuleForError(ruleID string, errorCode string) SARIFRule {
	return SARIFRule{
		ID: ruleID,
		ShortDescription: SARIFMessageContainer{
			Text: errorCode,
		},
	}
}

func SARIFResultForError(ruleID string, message string) SARIFResult {
	return SARIFResult{
		RuleID:  ruleID,
		Level:   "error",
		Message: SARIFMessageContainer{Text: message},
	}
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
		rules = append(rules, SARIFRule{
			ID: finding.ID,
			ShortDescription: SARIFMessageContainer{
				Text: finding.Summary,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	results := make([]SARIFResult, 0, len(findings))
	for _, finding := range findings {
		result := SARIFResult{
			RuleID:  finding.ID,
			Level:   SARIFLevelForSeverity(finding.Severity),
			Message: SARIFMessageContainer{Text: finding.Summary},
		}
		if finding.File != "" {
			result.Locations = []SARIFLocation{SARIFLocationForFile(finding.File, finding.Line)}
		}
		results = append(results, result)
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
