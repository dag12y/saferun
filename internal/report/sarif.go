package report

import (
	"fmt"
	"strings"

	"github.com/dag12y/saferun/internal/risk"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	ShortDescription SARIFMessage `json:"shortDescription"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// NewSARIFReport converts a SafeRun risk report into a SARIF v2.1.0 document
// suitable for GitHub Code Scanning ingestion.
func NewSARIFReport(version string, artifactURI string, result risk.Report) SARIFReport {
	if artifactURI == "" {
		artifactURI = "package.json"
	}

	rules := make([]SARIFRule, 0, len(result.Findings))
	seenRules := map[string]struct{}{}
	results := make([]SARIFResult, 0, len(result.Findings))

	for _, finding := range result.Findings {
		ruleID := sanitizeRuleID(finding.Name)
		if _, ok := seenRules[ruleID]; !ok {
			seenRules[ruleID] = struct{}{}
			rules = append(rules, SARIFRule{
				ID:               ruleID,
				ShortDescription: SARIFMessage{Text: finding.Name},
			})
		}

		msg := finding.Description
		if finding.Name != "" {
			msg = fmt.Sprintf("[%s] %s: %s", finding.Severity, finding.Name, finding.Description)
		}

		results = append(results, SARIFResult{
			RuleID:  ruleID,
			Level:   sarifLevel(finding.Severity),
			Message: SARIFMessage{Text: msg},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: artifactURI},
					},
				},
			},
		})
	}

	return SARIFReport{
		Version: "2.1.0",
		Schema:  sarifSchema,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "SafeRun",
						Version:        version,
						InformationURI: "https://github.com/dag12y/saferun",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

func sarifLevel(severity risk.Level) string {
	switch severity {
	case risk.Critical, risk.High:
		return "error"
	case risk.Medium:
		return "warning"
	default:
		return "note"
	}
}

func sanitizeRuleID(name string) string {
	if name == "" {
		return "saferun/finding"
	}
	var b strings.Builder
	b.WriteString("saferun/")
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
