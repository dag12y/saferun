package report

import (
	"encoding/json"
	"testing"

	"github.com/dag12y/saferun/internal/risk"
)

func TestNewSARIFReport(t *testing.T) {
	result := risk.Analyze([]risk.Finding{
		{Name: "postinstall: curl", Description: "Downloads data from a remote server", Severity: risk.High},
		{Name: ".env", Description: "Attempted access to environment file", Severity: risk.Critical},
		{Name: "README.txt", Description: "Hidden file", Severity: risk.Low},
	})

	sarif := NewSARIFReport("v1.0.6", "package.json", result)
	if sarif.Version != "2.1.0" {
		t.Fatalf("expected SARIF 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 || sarif.Runs[0].Tool.Driver.Name != "SafeRun" {
		t.Fatalf("unexpected SARIF runs: %#v", sarif.Runs)
	}
	if len(sarif.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 SARIF results, got %d", len(sarif.Runs[0].Results))
	}

	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty SARIF JSON")
	}
}
