package report

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
