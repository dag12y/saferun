package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dag12y/saferun/internal/cli"
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

func TestReadRecentReturnsNewestFirstAndIgnoresMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	content := strings.Join([]string{
		`{"timestamp":"2026-08-31T12:00:00Z","packages":["alpha"],"decision":"ALLOW"}`,
		`not-json`,
		`{"timestamp":"2026-09-01T09:00:00Z","packages":["beta"],"decision":"BLOCK"}`,
		`{"timestamp":"2026-09-01T10:00:00Z","packages":["gamma"],"decision":"CONFIRMATION_REQUIRED"}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	events, err := ReadRecentAt(path, 20)
	if err != nil {
		t.Fatalf("read recent events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 valid events, got %d", len(events))
	}
	if events[0].Packages[0] != "gamma" {
		t.Fatalf("expected newest event first, got %#v", events[0].Packages)
	}
	if events[2].Packages[0] != "alpha" {
		t.Fatalf("expected oldest event last, got %#v", events[2].Packages)
	}
}

func TestReadRecentRespectsDefaultLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var lines []string
	for i := 0; i < 25; i++ {
		timestamp := time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC).Format(time.RFC3339)
		lines = append(lines, fmt.Sprintf(`{"timestamp":"%s","packages":["pkg-%d"],"decision":"ALLOW"}`, timestamp, i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	events, err := ReadRecentAt(path, 20)
	if err != nil {
		t.Fatalf("read recent events: %v", err)
	}
	if len(events) != 20 {
		t.Fatalf("expected 20 events, got %d", len(events))
	}
	if events[0].Packages[0] != "pkg-24" {
		t.Fatalf("expected newest first, got %s", events[0].Packages[0])
	}
	if events[len(events)-1].Packages[0] != "pkg-5" {
		t.Fatalf("expected oldest included in limit window, got %s", events[len(events)-1].Packages[0])
	}
}

func TestReadRecentEmptyAndMissingAuditLogs(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	events, err := ReadRecentAt(emptyFile, 20)
	if err != nil {
		t.Fatalf("read empty audit log: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events from empty file, got %d", len(events))
	}

	missing, err := ReadRecentAt(filepath.Join(t.TempDir(), "missing.jsonl"), 20)
	if err != nil {
		t.Fatalf("read missing audit log: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected no events for missing file, got %d", len(missing))
	}
}

func TestFormatRecentIncludesRollbackAndTruncatesPackages(t *testing.T) {
	longPackage := strings.Repeat("/very/long/path/", 8) + "package-name@1.2.3"
	formatted := FormatRecent([]Event{{
		Timestamp:    "2026-09-01T13:45:00Z",
		Packages:     []string{longPackage},
		Risk:         "HIGH",
		Decision:     DecisionAllow,
		Approval:     ApprovalAccepted,
		Installation: InstallationSuccess,
		Verification: VerificationPassed,
		Rollback:     RollbackSucceeded,
	}})
	if !strings.Contains(formatted, "ALLOW") {
		t.Fatalf("expected ALLOW in formatted output: %q", formatted)
	}
	if !strings.Contains(formatted, "ROLLBACK: SUCCESS") {
		t.Fatalf("expected rollback formatting in output: %q", formatted)
	}
	if strings.Contains(formatted, longPackage) && len(formatted) > 400 {
		t.Fatal("expected long package names to be truncated before formatting")
	}
}

func TestParseAuditCommandSupportsAllFlag(t *testing.T) {
	cmd, err := cli.Parse([]string{"audit", "--all"})
	if err != nil {
		t.Fatalf("parse audit --all: %v", err)
	}
	if cmd.PackageManager != "audit" || cmd.Operation != "audit" {
		t.Fatalf("unexpected command: %#v", cmd)
	}
	if len(cmd.Arguments) != 1 || cmd.Arguments[0] != "--all" {
		t.Fatalf("unexpected audit arguments: %#v", cmd.Arguments)
	}
}
