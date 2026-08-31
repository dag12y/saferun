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
			{
				Path: "SAFERUN_TEST_ARTIFACT.txt",
			},
		},
	}

	findings := AnalyzeFileChanges(changes)

	if len(findings) != 2 {
		t.Fatalf(
			"expected 2 findings, got %d",
			len(findings),
		)
	}

	if findings[0].Severity != "HIGH" && findings[1].Severity != "HIGH" {
		t.Fatalf("expected HIGH severity in a suspicious artifact finding")
	}
}
