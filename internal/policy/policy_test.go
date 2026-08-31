package policy

import (
	"testing"

	"github.com/dag12y/saferun/internal/risk"
)

func TestEvaluateNoFindingsAllows(t *testing.T) {
	decision, reason, err := Evaluate(risk.Report{Level: risk.Low, Score: 0})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Allow {
		t.Fatalf("expected ALLOW, got %v", decision)
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %q", reason)
	}
}

func TestEvaluateLowFindingAllows(t *testing.T) {
	decision, _, err := Evaluate(risk.Report{Level: risk.Low, Score: 1})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Allow {
		t.Fatalf("expected ALLOW, got %v", decision)
	}
}

func TestEvaluateMediumRequiresConfirmation(t *testing.T) {
	decision, reason, err := Evaluate(risk.Report{Level: risk.Medium, Score: 5})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != RequireConfirmation {
		t.Fatalf("expected REQUIRE_CONFIRMATION, got %v", decision)
	}
	if reason == "" {
		t.Fatal("expected reason for medium risk")
	}
}

func TestEvaluateHighBlocks(t *testing.T) {
	decision, reason, err := Evaluate(risk.Report{Level: risk.High, Score: 10})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Block {
		t.Fatalf("expected BLOCK, got %v", decision)
	}
	if reason == "" {
		t.Fatal("expected high-risk reason")
	}
}

func TestEvaluateCriticalBlocks(t *testing.T) {
	decision, reason, err := Evaluate(risk.Report{Level: risk.Critical, Score: 20})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Block {
		t.Fatalf("expected BLOCK, got %v", decision)
	}
	if reason == "" {
		t.Fatal("expected critical-risk reason")
	}
}

func TestEvaluateMultipleFindingsHighBlocks(t *testing.T) {
	decision, _, err := Evaluate(risk.Report{Level: risk.High, Score: 15})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Block {
		t.Fatalf("expected BLOCK, got %v", decision)
	}
}

func TestEvaluateMultipleFindingsCriticalBlocks(t *testing.T) {
	decision, _, err := Evaluate(risk.Report{Level: risk.Critical, Score: 25})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Block {
		t.Fatalf("expected BLOCK, got %v", decision)
	}
}

func TestEvaluateCriticalOverridesLowerScore(t *testing.T) {
	decision, _, err := Evaluate(risk.Report{Level: risk.Critical, Score: 26})
	if err != nil {
		t.Fatalf("Evaluate returned unexpected error: %v", err)
	}
	if decision != Block {
		t.Fatalf("expected BLOCK, got %v", decision)
	}
}

func TestEvaluateDeterministic(t *testing.T) {
	first, _, err1 := Evaluate(risk.Report{Level: risk.Medium, Score: 5})
	second, _, err2 := Evaluate(risk.Report{Level: risk.Medium, Score: 5})
	if err1 != nil || err2 != nil {
		t.Fatal("unexpected errors")
	}
	if first != second {
		t.Fatalf("expected deterministic result, got %v and %v", first, second)
	}
}

func TestEvaluateUnknownRiskFailsClosed(t *testing.T) {
	decision, _, err := Evaluate(risk.Report{Level: risk.Level("UNKNOWN")})
	if err == nil {
		t.Fatal("expected error for unknown state")
	}
	if decision != Block {
		t.Fatalf("expected BLOCK fail-closed, got %v", decision)
	}
}
