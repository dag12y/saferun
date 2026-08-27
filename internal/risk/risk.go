package risk

type Level string

const (
	Low      Level = "LOW"
	Medium   Level = "MEDIUM"
	High     Level = "HIGH"
	Critical Level = "CRITICAL"
)

type Finding struct {
	Name        string
	Description string
	Severity    Level
}

type Report struct {
	Level    Level
	Findings []Finding
}

func Analyze(findings []Finding) Report {
	level := Low

	for _, finding := range findings {
		if severityValue(finding.Severity) > severityValue(level) {
			level = finding.Severity
		}
	}

	return Report{
		Level:    level,
		Findings: findings,
	}
}

func severityValue(level Level) int {
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
		return 0
	}
}
