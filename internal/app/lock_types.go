package app

type installLock struct {
	Schema      string             `json:"schema"`
	Name        string             `json:"name"`
	InstalledAt string             `json:"installed_at"`
	Source      lockSource         `json:"source"`
	Skill       lockSkill          `json:"skill"`
	Policy      lockPolicy         `json:"policy"`
	Findings    lockFindingSummary `json:"findings"`
}

type lockSource struct {
	Type  string `json:"type"`
	Input string `json:"input"`
	Kind  string `json:"kind"`
}

type lockSkill struct {
	RootSHA256 string         `json:"root_sha256"`
	Files      []lockFileHash `json:"files"`
}

type lockFileHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type lockPolicy struct {
	Profile           string                  `json:"profile"`
	Decision          string                  `json:"decision"`
	SeverityOverrides []severityOverrideAudit `json:"severity_overrides"`
}

type lockFindingSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}
