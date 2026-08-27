package analyzer

import "strings"

type ScriptFinding struct {
	Pattern     string
	Description string
	Severity    string
}

func AnalyzeScript(command string) []ScriptFinding {
	commandLower := strings.ToLower(command)

	var findings []ScriptFinding

	patterns := []struct {
		pattern     string
		description string
		severity    string
	}{
		{
			"curl",
			"Downloads data from a remote server",
			"MEDIUM",
		},
		{
			"wget",
			"Downloads data from a remote server",
			"MEDIUM",
		},
		{
			"invoke-webrequest",
			"Downloads data from a remote server",
			"MEDIUM",
		},
		{
			"eval",
			"Executes dynamically constructed code",
			"HIGH",
		},
		{
			"base64",
			"Uses Base64 encoding/decoding",
			"MEDIUM",
		},
		{
			"chmod",
			"Changes file permissions",
			"MEDIUM",
		},
		{
			"sh -c",
			"Executes a shell command",
			"MEDIUM",
		},
		{
			"bash -c",
			"Executes a shell command",
			"MEDIUM",
		},
		{
			".ssh",
			"References SSH configuration or credentials",
			"HIGH",
		},
		{
			".aws",
			"References AWS configuration or credentials",
			"HIGH",
		},
		{
			"process.env",
			"Accesses environment variables",
			"MEDIUM",
		},
	}

	for _, item := range patterns {
		if strings.Contains(commandLower, strings.ToLower(item.pattern)) {
			findings = append(findings, ScriptFinding{
				Pattern:     item.pattern,
				Description: item.description,
				Severity:    item.severity,
			})
		}
	}

	return findings
}
