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

func TestAnalyzeScoreBoundaries(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     Level
	}{
		{name: "no findings", want: Low},
		{name: "one low", findings: []Finding{{Name: "a", Severity: Low}}, want: Low},
		{name: "one medium", findings: []Finding{{Name: "a", Severity: Medium}}, want: Medium},
		{name: "one high", findings: []Finding{{Name: "a", Severity: High}}, want: High},
		{name: "one critical", findings: []Finding{{Name: "a", Severity: Critical}}, want: Critical},
		{name: "score 4 low", findings: []Finding{{Name: "a", Severity: Low}, {Name: "b", Severity: Low}, {Name: "c", Severity: Low}, {Name: "d", Severity: Low}}, want: Low},
		{name: "score 5 medium", findings: []Finding{{Name: "a", Severity: Medium}}, want: Medium},
		{name: "score 9 medium", findings: []Finding{{Name: "a", Severity: Medium}, {Name: "b", Severity: Low}, {Name: "c", Severity: Low}, {Name: "d", Severity: Low}, {Name: "e", Severity: Low}}, want: Medium},
		{name: "score 10 high", findings: []Finding{{Name: "a", Severity: High}}, want: High},
		{name: "score 19 high", findings: []Finding{{Name: "a", Severity: Medium}, {Name: "b", Severity: Medium}, {Name: "c", Severity: Medium}, {Name: "d", Severity: Low}, {Name: "e", Severity: Low}, {Name: "f", Severity: Low}, {Name: "g", Severity: Low}}, want: High},
		{name: "score 20 critical", findings: []Finding{{Name: "a", Severity: Medium}, {Name: "b", Severity: Medium}, {Name: "c", Severity: High}}, want: Critical},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := Analyze(tc.findings)
			if report.Level != tc.want {
				t.Fatalf("expected %s, got %s (score=%d)", tc.want, report.Level, report.Score)
			}
		})
	}
}

func TestAnalyzeCriticalOverridesScore(t *testing.T) {
	report := Analyze([]Finding{
		{Name: "low signal", Severity: Low},
		{Name: "medium signal", Severity: Medium},
		{Name: "critical signal", Severity: Critical},
	})

	if report.Level != Critical {
		t.Fatalf("critical finding should override score, expected CRITICAL, got %s", report.Level)
	}
	if report.Score != 26 {
		t.Fatalf("expected total score 26, got %d", report.Score)
	}
}

func TestAnalyzeAccumulatesMultipleFindings(t *testing.T) {
	report := Analyze([]Finding{
		{Name: "one", Severity: Medium},
		{Name: "two", Severity: Medium},
		{Name: "three", Severity: High},
	})

	if report.Score != 20 {
		t.Fatalf("expected score 20, got %d", report.Score)
	}
	if report.Level != Critical {
		t.Fatalf("expected CRITICAL, got %s", report.Level)
	}
}
