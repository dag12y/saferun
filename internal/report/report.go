package report

import (
	"strings"
	"time"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/policy"
	"github.com/dag12y/saferun/internal/risk"
)

type SecurityReport struct {
	Package   string    `json:"package"`
	Version   string    `json:"version"`
	Risk      Risk      `json:"risk"`
	Analysis  Analysis  `json:"analysis"`
	Policy    Policy    `json:"policy"`
	Timestamp time.Time `json:"timestamp"`
}

type Risk struct {
	Level    risk.Level     `json:"level"`
	Score    int            `json:"score"`
	Findings []risk.Finding `json:"findings"`
}

type Analysis struct {
	Behavior  Behavior `json:"behavior"`
	Processes []string `json:"processes"`
	Network   []string `json:"network"`
	Files     []string `json:"files"`
}

type Behavior struct {
	Suspicious bool `json:"suspicious"`
}

type Policy struct {
	Decision string `json:"decision"`
}

type ProjectSecurityReport struct {
	Operation        string                 `json:"operation"`
	Scope            string                 `json:"scope"`
	Project          string                 `json:"project"`
	PackagesAnalyzed int                    `json:"packages_analyzed"`
	RiskSummary      map[string]int         `json:"risk_summary"`
	Decision         string                 `json:"decision"`
	Packages         []ProjectPackageReport `json:"packages"`
	Analysis         Analysis               `json:"analysis"`
	Timestamp        time.Time              `json:"timestamp"`
}

type ProjectPackageReport struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Risk    Risk   `json:"risk"`
}

func NewSecurityReport(pkgName, version string, result risk.Report, behavior []analyzer.BehaviorFinding, processes []analyzer.ProcessFinding, network []string, files []analyzer.FileFinding, decision policy.Decision) SecurityReport {
	findings := make([]risk.Finding, len(result.Findings))
	copy(findings, result.Findings)
	processNames := make([]string, 0, len(processes))
	for _, finding := range processes {
		processNames = append(processNames, finding.Command)
	}
	filePaths := make([]string, 0, len(files))
	for _, finding := range files {
		filePaths = append(filePaths, finding.Path)
	}
	networkConnections := make([]string, len(network))
	copy(networkConnections, network)
	return SecurityReport{
		Package: pkgName,
		Version: version,
		Risk:    Risk{Level: result.Level, Score: result.Score, Findings: findings},
		Analysis: Analysis{
			Behavior:  Behavior{Suspicious: len(behavior) > 0},
			Processes: processNames,
			Network:   networkConnections,
			Files:     filePaths,
		},
		Policy:    Policy{Decision: decision.String()},
		Timestamp: time.Now().UTC(),
	}
}

func NewProjectSecurityReport(project string, result risk.Report, packages []ProjectPackageInput, behavior []analyzer.BehaviorFinding, processes []analyzer.ProcessFinding, network []string, decision policy.Decision) ProjectSecurityReport {
	summary := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	packageResults := make([]ProjectPackageReport, 0, len(packages))
	for _, pkg := range packages {
		packageRisk := risk.Analyze(pkg.Findings)
		summary[strings.ToLower(string(packageRisk.Level))]++
		packageResults = append(packageResults, ProjectPackageReport{
			Name: pkg.Name, Version: pkg.Version,
			Risk: Risk{Level: packageRisk.Level, Score: packageRisk.Score, Findings: packageRisk.Findings},
		})
	}
	return ProjectSecurityReport{
		Operation: "install", Scope: "project", Project: project,
		PackagesAnalyzed: len(packageResults), RiskSummary: summary,
		Decision: decision.String(), Packages: packageResults,
		Analysis: Analysis{
			Behavior:  Behavior{Suspicious: len(behavior) > 0},
			Processes: processNames(processes), Network: append([]string{}, network...),
			Files: []string{},
		},
		Timestamp: time.Now().UTC(),
	}
}

type ProjectPackageInput struct {
	Name     string
	Version  string
	Findings []risk.Finding
}

func processNames(processes []analyzer.ProcessFinding) []string {
	result := make([]string, 0, len(processes))
	for _, finding := range processes {
		result = append(result, finding.Command)
	}
	return result
}
