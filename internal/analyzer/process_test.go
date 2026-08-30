package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeProcRootDetectsSuspiciousProcesses(t *testing.T) {
	root := t.TempDir()

	writeProcCmd := func(pid string, cmd string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd+"\x00"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeProcCmd("101", "npm install lodash")
	writeProcCmd("202", "node /usr/local/bin/npm install lodash")
	writeProcCmd("303", "curl -fsS https://example.com/payload")
	writeProcCmd("404", "bash -c curl -fsS https://example.com")
	writeProcCmd("505", "sh -c npm install lodash")

	findings, err := AnalyzeProcRoot(root)
	if err != nil {
		t.Fatalf("AnalyzeProcRoot returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected suspicious process findings")
	}

	seenSuspicious := map[string]bool{}
	for _, finding := range findings {
		seenSuspicious[finding.Command] = true
	}

	if !seenSuspicious["curl"] {
		t.Fatalf("expected curl to be flagged, got %#v", findings)
	}
	if !seenSuspicious["bash"] {
		t.Fatalf("expected bash to be flagged when used for network access, got %#v", findings)
	}
	if seenSuspicious["npm"] || seenSuspicious["node"] || seenSuspicious["sh"] {
		t.Fatalf("expected expected processes to be ignored, got %#v", findings)
	}
}

func TestAnalyzeProcessOutputDoesNotFlagOrdinaryInstallShells(t *testing.T) {
	findings := AnalyzeProcessOutput("npm install lodash\nnode /usr/local/bin/npm install lodash\nsh -c npm install lodash")
	if len(findings) != 0 {
		t.Fatalf("expected ordinary install processes to stay clean, got %#v", findings)
	}
}
