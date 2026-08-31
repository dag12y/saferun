package risk

import "sort"

type Level string

const (
	Low      Level = "LOW"
	Medium   Level = "MEDIUM"
	High     Level = "HIGH"
	Critical Level = "CRITICAL"
)

var scoreBySeverity = map[Level]int{
	Low:      1,
	Medium:   5,
	High:     10,
	Critical: 20,
}

var thresholdOrder = []Level{Low, Medium, High, Critical}

type Finding struct {
	Name        string
	Description string
	Severity    Level
}

type Report struct {
	Level        Level
	Score        int
	FindingCount int
	Findings     []Finding
}

func Analyze(findings []Finding) Report {
	sorted := append([]Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].Description < sorted[j].Description
	})

	total := 0
	for _, finding := range sorted {
		total += scoreForSeverity(finding.Severity)
		if finding.Severity == Critical {
			return Report{
				Level:        Critical,
				Score:        total,
				FindingCount: len(sorted),
				Findings:     sorted,
			}
		}
	}

	return Report{
		Level:        levelFromScore(total),
		Score:        total,
		FindingCount: len(sorted),
		Findings:     sorted,
	}
}

func scoreForSeverity(level Level) int {
	if value, ok := scoreBySeverity[level]; ok {
		return value
	}
	return 0
}

func severityRank(level Level) int {
	switch level {
	case Low:
		return 0
	case Medium:
		return 1
	case High:
		return 2
	case Critical:
		return 3
	default:
		return -1
	}
}

func levelFromScore(score int) Level {
	switch {
	case score >= 20:
		return Critical
	case score >= 10:
		return High
	case score >= 5:
		return Medium
	default:
		return Low
	}
}
