package analyzer

import "strings"

type BehaviorFinding struct {
	Path        string
	Description string
	Severity    string
}

func AnalyzeFileChanges(changes FileChanges) []BehaviorFinding {
	var findings []BehaviorFinding

	for _, file := range changes.Created {

		path := strings.ToLower(file.Path)

		// Ignore normal npm installation files
		if strings.HasPrefix(path, "node_modules/") {
			continue
		}

		if strings.Contains(path, ".ssh") {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: "Attempted access to SSH files",
				Severity:    "HIGH",
			})
			continue
		}

		if strings.Contains(path, ".aws") {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: "Attempted access to AWS credentials",
				Severity:    "HIGH",
			})
			continue
		}

		if strings.HasSuffix(path, ".sh") {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: "Created shell script",
				Severity:    "MEDIUM",
			})
			continue
		}

		if strings.Contains(path, "saferun_test_artifact") || strings.Contains(path, "saferun_test_artifact.txt") {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: "Created a test artifact file for SafeRun detection",
				Severity:    "MEDIUM",
			})
		}
	}

	return findings
}
