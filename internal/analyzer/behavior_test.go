package analyzer

import "testing"

func TestAnalyzeFileChanges(t *testing.T) {

	changes := FileChanges{
		Created: []FileSnapshot{
			{
				Path: "node_modules/test/index.js",
			},
			{
				Path: ".ssh/id_rsa",
			},
		},
	}

	findings := AnalyzeFileChanges(changes)

	if len(findings) != 1 {
		t.Fatalf(
			"expected 1 finding, got %d",
			len(findings),
		)
	}

	if findings[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH severity")
	}
}
