package analyzer

import "testing"

func TestAnalyzeScriptDetectsCurl(t *testing.T) {
	findings := AnalyzeScript("curl https://example.com/install.sh")

	if len(findings) == 0 {
		t.Fatal("expected curl to be detected")
	}

	if findings[0].Pattern != "curl" {
		t.Fatalf("expected curl, got %s", findings[0].Pattern)
	}
}

func TestAnalyzeScriptDetectsEval(t *testing.T) {
	findings := AnalyzeScript("eval $(base64 -d payload)")

	if len(findings) == 0 {
		t.Fatal("expected suspicious behavior to be detected")
	}
}

func TestAnalyzeScriptCleanCommand(t *testing.T) {
	findings := AnalyzeScript("node build.js")

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
