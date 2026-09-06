package report

import (
	"encoding/json"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/policy"
	"github.com/dag12y/saferun/internal/risk"
)

func TestNewSecurityReportJSONContainsRequiredFields(t *testing.T) {
	securityReport := NewSecurityReport("lodash", "4.18.1", risk.Analyze(nil), nil, nil, []string{"registry.npmjs.org:443"}, nil, policy.Allow)
	data, err := json.Marshal(securityReport)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	for _, field := range []string{"package", "version", "risk", "analysis", "policy", "timestamp"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required field %q", field)
		}
	}
	if decoded["package"] != "lodash" {
		t.Fatalf("package = %v, want lodash", decoded["package"])
	}
	analysis := decoded["analysis"].(map[string]any)
	if analysis["network"].([]any)[0] != "registry.npmjs.org:443" {
		t.Fatalf("unexpected network analysis: %v", analysis["network"])
	}
}

func TestNewSecurityReportMarksSuspiciousBehavior(t *testing.T) {
	securityReport := NewSecurityReport("pkg", "1.0.0", risk.Analyze(nil), []analyzer.BehaviorFinding{{Path: ".ssh"}}, nil, nil, nil, policy.Block)
	if !securityReport.Analysis.Behavior.Suspicious {
		t.Fatal("expected behavior to be suspicious")
	}
}
