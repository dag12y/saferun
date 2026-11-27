package analyzer

import (
	"path/filepath"
	"strings"
)

type BehaviorFinding struct {
	Path        string
	Description string
	Severity    string
}

func normalizeBehaviorPath(p string) string {
	return strings.ToLower(strings.ReplaceAll(filepath.ToSlash(p), `\`, "/"))
}

func isIgnoredInstallPath(normalizedPath string) bool {
	return strings.HasPrefix(normalizedPath, "node_modules/") ||
		normalizedPath == "package.json" ||
		normalizedPath == "package-lock.json"
}

func isSensitivePath(normalizedPath string) (string, bool) {
	if strings.Contains(normalizedPath, ".ssh") {
		return "Attempted access to SSH files", true
	}
	if strings.Contains(normalizedPath, ".aws") {
		return "Attempted access to AWS credentials", true
	}
	if strings.Contains(normalizedPath, ".env") {
		return "Attempted access to environment file", true
	}
	if strings.HasPrefix(normalizedPath, ".git/") || strings.Contains(normalizedPath, "/.git/") {
		return "Attempted access to Git metadata", true
	}
	return "", false
}

func AnalyzeFileChanges(changes FileChanges) []BehaviorFinding {
	var findings []BehaviorFinding

	for _, file := range changes.Created {
		path := normalizeBehaviorPath(file.Path)

		// Ignore normal npm installation files.
		if strings.HasPrefix(path, "node_modules/") {
			continue
		}

		if desc, ok := isSensitivePath(path); ok {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: desc,
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

	for _, file := range changes.Modified {
		path := normalizeBehaviorPath(file.Path)
		if isIgnoredInstallPath(path) {
			continue
		}
		if desc, ok := isSensitivePath(path); ok {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: desc,
				Severity:    "HIGH",
			})
			continue
		}
		findings = append(findings, BehaviorFinding{
			Path:        file.Path,
			Description: "Modified existing project file",
			Severity:    "MEDIUM",
		})
	}

	for _, file := range changes.Deleted {
		path := normalizeBehaviorPath(file.Path)
		if isIgnoredInstallPath(path) {
			continue
		}
		if desc, ok := isSensitivePath(path); ok {
			findings = append(findings, BehaviorFinding{
				Path:        file.Path,
				Description: desc,
				Severity:    "HIGH",
			})
			continue
		}
		findings = append(findings, BehaviorFinding{
			Path:        file.Path,
			Description: "Deleted existing project file",
			Severity:    "MEDIUM",
		})
	}

	return findings
}
