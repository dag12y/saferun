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

func TestAnalyzeFileChangesModifiedDeletedAndWindowsPaths(t *testing.T) {
	changes := FileChanges{
		Created: []FileSnapshot{
			{Path: `node_modules\pkg\setup.sh`},
		},
		Modified: []FileSnapshot{
			{Path: "package-lock.json"},
			{Path: "src/index.js"},
		},
		Deleted: []FileSnapshot{
			{Path: ".env"},
		},
	}

	findings := AnalyzeFileChanges(changes)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (modified src/index.js and deleted .env), got %#v", findings)
	}
	if findings[0].Path != "src/index.js" || findings[0].Severity != "MEDIUM" {
		t.Fatalf("unexpected modified finding: %#v", findings[0])
	}
	if findings[1].Path != ".env" || findings[1].Severity != "HIGH" {
		t.Fatalf("unexpected deleted finding: %#v", findings[1])
	}
}
