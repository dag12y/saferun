package report

import (
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
