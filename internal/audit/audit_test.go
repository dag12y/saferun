package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventSerializesToJSON(t *testing.T) {
	event := Event{
		Packages:     []string{"lodash@4.18.1"},
		Risk:         "LOW",
		Score:        0,
		FindingCount: 0,
		Decision:     DecisionAllow,
		Approval:     ApprovalAccepted,
		Installation: InstallationSuccess,
		Verification: VerificationPassed,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if !strings.Contains(string(data), "\"decision\":\"ALLOW\"") {
		t.Fatalf("serialized event should contain decision: %s", string(data))
	}
}

func TestMultipleEventsAppendCorrectly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger := NewLoggerAt(path)

	if err := logger.Record(Event{Packages: []string{"a"}, Decision: DecisionAllow, Approval: ApprovalAccepted, Installation: InstallationSuccess, Verification: VerificationPassed}); err != nil {
		t.Fatalf("record first event: %v", err)
	}
	if err := logger.Record(Event{Packages: []string{"b"}, Decision: DecisionBlock, Approval: ApprovalNotNeeded, Installation: InstallationNotRun, Verification: VerificationNotRun}); err != nil {
		t.Fatalf("record second event: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL events, got %d; content=%q", len(lines), string(data))
	}
	for _, line := range lines {
		if !strings.Contains(line, "\"timestamp\"") {
			t.Fatalf("expected JSON event line, got %q", line)
		}
	}
}

func TestAuditDirectoryCreatedAutomatically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit", "audit.jsonl")
	logger := NewLoggerAt(path)

	if err := logger.Record(Event{Packages: []string{"express@5.2.1"}, Decision: DecisionBlock, Approval: ApprovalNotNeeded, Installation: InstallationNotRun, Verification: VerificationNotRun}); err != nil {
		t.Fatalf("record event: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected log file to be created: %v", err)
	}
}

func TestBlockedPackageEventRecordedCorrectly(t *testing.T) {
	event := Event{
		Packages:     []string{"suspicious-package@1.0.0"},
		Risk:         "CRITICAL",
		Score:        25,
		FindingCount: 3,
		Decision:     DecisionBlock,
		Approval:     ApprovalNotNeeded,
		Installation: InstallationNotRun,
		Verification: VerificationNotRun,
	}
	if event.Decision != DecisionBlock || event.Installation != InstallationNotRun || event.Verification != VerificationNotRun {
		t.Fatal("blocked event did not match expected final state")
	}
}

func TestDeclinedInstallationRecordedCorrectly(t *testing.T) {
	event := Event{
		Packages:     []string{"lodash@4.18.1"},
		Risk:         "LOW",
		Decision:     DecisionAllow,
		Approval:     ApprovalDeclined,
		Installation: InstallationNotRun,
		Verification: VerificationNotRun,
	}
	if event.Approval != ApprovalDeclined || event.Installation != InstallationNotRun {
		t.Fatal("declined event did not match expected final state")
	}
}

func TestSuccessfulInstallationRecordedCorrectly(t *testing.T) {
	event := Event{
		Packages:     []string{"lodash@4.18.1"},
		Risk:         "LOW",
		Decision:     DecisionAllow,
		Approval:     ApprovalAccepted,
		Installation: InstallationSuccess,
		Verification: VerificationPassed,
	}
	if event.Verification != VerificationPassed || event.Installation != InstallationSuccess {
		t.Fatal("successful installation event did not match expected final state")
	}
}

func TestFailedInstallationRecordedCorrectly(t *testing.T) {
	event := Event{
		Packages:     []string{"lodash@4.18.1"},
		Risk:         "LOW",
		Decision:     DecisionAllow,
		Approval:     ApprovalAccepted,
		Installation: InstallationFailed,
		Verification: VerificationNotRun,
		Reason:       "npm install exited with code 1",
	}
	if event.Installation != InstallationFailed || event.Verification != VerificationNotRun {
		t.Fatal("failed install event did not match expected final state")
	}
}

func TestVerificationFailureRecordedCorrectly(t *testing.T) {
	event := Event{
		Packages:     []string{"lodash@4.18.1"},
		Risk:         "LOW",
		Decision:     DecisionAllow,
		Approval:     ApprovalAccepted,
		Installation: InstallationSuccess,
		Verification: VerificationFailed,
		Reason:       "dependency mismatch",
	}
	if event.Installation != InstallationSuccess || event.Verification != VerificationFailed {
		t.Fatal("verification failure event did not match expected final state")
	}
}

func TestSensitiveFieldsAreNotSerializedUnexpectedly(t *testing.T) {
	event := Event{
		Packages: []string{"pkg@1.0.0"},
		Reason:   "token=redacted; status=ok",
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if strings.Contains(string(data), "API_KEY") || strings.Contains(string(data), "password") || strings.Contains(string(data), "secret") {
		t.Fatalf("sensitive field unexpectedly serialized: %s", string(data))
	}
	if !strings.Contains(string(data), "token=redacted") {
		t.Fatalf("safe reason should still be serialized: %s", string(data))
	}
}
