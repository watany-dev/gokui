package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

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

type FindingsSARIFInput struct {
	SchemaVersion string
	PreRelease    bool
	SourceInput   string
	SourceKind    string
	Decision      string
	Rejected      bool
	Note          string
	Findings      []SARIFFinding
}

type UpdateSARIFSummary struct {
	Changed  int
	Rejected int
	Errors   int
}

type UpdateSARIFSkill struct {
	Name      string
	Status    string
	ErrorCode string
	RuleID    string
	Message   string
	Findings  []SARIFFinding
}

type UpdateSARIFInput struct {
	SchemaVersion            string
	Target                   string
	Note                     string
	Summary                  UpdateSARIFSummary
	Skills                   []UpdateSARIFSkill
	StatusError              string
	StatusRejected           string
	ErrorDecision            string
	RejectedDecision         string
	ChangedDecision          string
	PassDecision             string
	SourceKind               string
	StatusFallbackRuleID     string
	StatusFallbackSeverity   string
	ExecutionFailureOnReject bool
}

func PreReleaseSARIFProperties(schemaVersion string, sourceInput string, sourceKind string, decision string, note string) SARIFProperties {
	return SARIFProperties{
		SchemaVersion: schemaVersion,
		PreRelease:    true,
		SourceInput:   sourceInput,
		SourceKind:    sourceKind,
		Decision:      decision,
		Note:          note,
	}
}

func PreReleaseSARIFErrorProperties(schemaVersion string, sourceInput string, sourceKind string, decision string, note string, errorCode string) SARIFProperties {
	return PreReleaseSARIFProperties(schemaVersion, sourceInput, sourceKind, decision, note+"; error_code="+errorCode)
}

func SARIFDocumentForFindingsInput(input FindingsSARIFInput) SARIFDocument {
	properties := PreReleaseSARIFProperties(
		input.SchemaVersion,
		input.SourceInput,
		input.SourceKind,
		input.Decision,
		input.Note,
	)
	properties.PreRelease = input.PreRelease
	return SARIFDocumentForFindings(
		input.Findings,
		!input.Rejected,
		properties,
	)
}

func SARIFDocumentForUpdate(input UpdateSARIFInput) SARIFDocument {
	decision := input.PassDecision
	if input.Summary.Errors > 0 {
		decision = input.ErrorDecision
	} else if input.Summary.Rejected > 0 {
		decision = input.RejectedDecision
	} else if input.Summary.Changed > 0 {
		decision = input.ChangedDecision
	}

	findings := updateSARIFFindings(input)
	sarif := SARIFDocumentForFindingsInput(FindingsSARIFInput{
		SchemaVersion: input.SchemaVersion,
		PreRelease:    true,
		SourceInput:   input.Target,
		SourceKind:    input.SourceKind,
		Decision:      decision,
		Rejected:      input.Summary.Rejected > 0,
		Note:          input.Note,
		Findings:      findings,
	})
	if len(sarif.Runs) > 0 {
		executionSuccessful := input.Summary.Errors == 0
		if input.ExecutionFailureOnReject {
			executionSuccessful = executionSuccessful && input.Summary.Rejected == 0
		}
		sarif.Runs[0].Invocations = []SARIFInvocation{{ExecutionSuccessful: executionSuccessful}}
	}
	return sarif
}

func updateSARIFFindings(input UpdateSARIFInput) []SARIFFinding {
	findings := make([]SARIFFinding, 0, 64)
	for _, skill := range input.Skills {
		if len(skill.Findings) > 0 {
			for _, finding := range skill.Findings {
				filePath := finding.File
				if filePath != "" {
					filePath = filepath.ToSlash(filepath.Join(skill.Name, filePath))
				}
				summary := finding.Summary
				if strings.TrimSpace(summary) == "" {
					summary = fmt.Sprintf("%s finding in %s", finding.ID, skill.Name)
				}
				findings = append(findings, SARIFFinding{
					ID:       finding.ID,
					Severity: finding.Severity,
					File:     filePath,
					Line:     finding.Line,
					Summary:  summary,
				})
			}
			continue
		}
		if skill.Status != input.StatusError && skill.Status != input.StatusRejected {
			continue
		}
		ruleID := skill.RuleID
		if ruleID == "" {
			ruleID = skill.ErrorCode
		}
		if ruleID == "" {
			ruleID = input.StatusFallbackRuleID
		}
		summary := skill.Message
		if strings.TrimSpace(summary) == "" {
			summary = fmt.Sprintf("%s: %s", skill.Status, skill.Name)
		}
		findings = append(findings, SARIFFinding{
			ID:       ruleID,
			Severity: input.StatusFallbackSeverity,
			File:     filepath.ToSlash(skill.Name),
			Line:     1,
			Summary:  summary,
		})
	}
	return findings
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

type LockVerifySARIFCheck struct {
	Code   string
	Name   string
	OK     bool
	Detail string
}

type LockVerifySARIFDrift struct {
	MissingFiles    []string
	ChangedFiles    []string
	UnexpectedFiles []string
}

type LockVerifySARIFInput struct {
	Status         string
	VerifiedStatus string
	FileDigestCode string
	Checks         []LockVerifySARIFCheck
	Drift          LockVerifySARIFDrift
	Properties     SARIFProperties
}

type SARIFErrorInput struct {
	RuleID        string
	ErrorCode     string
	Message       string
	SchemaVersion string
	SourceInput   string
	SourceKind    string
	Decision      string
	Note          string
}

func SARIFErrorDocumentForInput(input SARIFErrorInput) SARIFDocument {
	return SARIFErrorDocument(
		input.RuleID,
		input.ErrorCode,
		input.Message,
		PreReleaseSARIFErrorProperties(input.SchemaVersion, input.SourceInput, input.SourceKind, input.Decision, input.Note, input.ErrorCode),
	)
}

func SARIFDocumentForLockVerify(input LockVerifySARIFInput) SARIFDocument {
	decision := "PASS"
	if input.Status != input.VerifiedStatus {
		decision = "DRIFTED"
	}
	properties := input.Properties
	properties.Decision = decision

	rules := make([]SARIFRule, 0, len(input.Checks))
	for _, check := range input.Checks {
		rules = append(rules, SARIFRuleForFinding(check.Code, "lock verify check: "+check.Name))
	}
	SortSARIFRulesByID(rules)

	results := make([]SARIFResult, 0, 32)
	for _, check := range input.Checks {
		if check.OK {
			continue
		}
		results = append(results, SARIFResultForFinding(check.Code, "error", check.Detail, nil))
		if check.Code != input.FileDigestCode {
			continue
		}
		for _, path := range input.Drift.MissingFiles {
			results = append(results, driftSARIFResult(check.Code, path, "missing file listed in lock"))
		}
		for _, path := range input.Drift.ChangedFiles {
			results = append(results, driftSARIFResult(check.Code, path, "changed file hash or size"))
		}
		for _, path := range input.Drift.UnexpectedFiles {
			results = append(results, driftSARIFResult(check.Code, path, "unexpected file not listed in lock"))
		}
	}
	SortSARIFResultsByRuleLocationMessage(results)

	return SARIFDocumentForRun(rules, results, input.Status == input.VerifiedStatus, properties)
}

func driftSARIFResult(ruleID string, path string, reason string) SARIFResult {
	message := reason + ": " + path
	if strings.TrimSpace(path) == "" {
		return SARIFResultForFinding(ruleID, "error", message, nil)
	}
	return SARIFResultForFinding(
		ruleID,
		"error",
		message,
		[]SARIFLocation{SARIFLocationForFile(path, 0)},
	)
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
