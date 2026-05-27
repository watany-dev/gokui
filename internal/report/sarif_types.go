package report

type SARIFDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Properties  SARIFProperties   `json:"properties"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string                `json:"id"`
	ShortDescription SARIFMessageContainer `json:"shortDescription"`
}

type SARIFMessageContainer struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string                `json:"ruleId"`
	Level     string                `json:"level"`
	Message   SARIFMessageContainer `json:"message"`
	Locations []SARIFLocation       `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type SARIFProperties struct {
	SchemaVersion string `json:"schema_version"`
	PreRelease    bool   `json:"pre_release"`
	SourceInput   string `json:"source_input"`
	SourceKind    string `json:"source_kind"`
	Decision      string `json:"decision"`
	Note          string `json:"note"`
}
