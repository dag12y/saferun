package risk

import "testing"

func TestAnalyzeHighestSeverity(t *testing.T) {
	findings := []Finding{
		{
			Name:     "lifecycle script",
			Severity: Medium,
		},
		{
			Name:     "network access",
			Severity: High,
		},
	}

	report := Analyze(findings)

	if report.Level != High {
		t.Fatalf("expected HIGH, got %s", report.Level)
	}
}

func TestAnalyzeNoFindings(t *testing.T) {
	report := Analyze(nil)

	if report.Level != Low {
		t.Fatalf("expected LOW, got %s", report.Level)
	}
}
