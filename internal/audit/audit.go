package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Decision string

type Approval string

type Installation string

type Verification string

type Rollback string

const (
	DecisionAllow                Decision = "ALLOW"
	DecisionConfirmationRequired Decision = "CONFIRMATION_REQUIRED"
	DecisionBlock                Decision = "BLOCK"

	ApprovalAccepted  Approval = "ACCEPTED"
	ApprovalDeclined  Approval = "DECLINED"
	ApprovalNotNeeded Approval = "NOT_REQUIRED"

	InstallationSuccess Installation = "SUCCESS"
	InstallationFailed  Installation = "FAILED"
	InstallationNotRun  Installation = "NOT_EXECUTED"

	VerificationPassed Verification = "PASSED"
	VerificationFailed Verification = "FAILED"
	VerificationNotRun Verification = "NOT_RUN"

	RollbackNotRequired Rollback = "NOT_REQUIRED"
	RollbackSucceeded   Rollback = "SUCCESS"
	RollbackFailed      Rollback = "FAILED"
)

type Event struct {
	Timestamp    string       `json:"timestamp"`
	Packages     []string     `json:"packages"`
	Risk         string       `json:"risk,omitempty"`
	Score        int          `json:"score,omitempty"`
	FindingCount int          `json:"findings,omitempty"`
	Decision     Decision     `json:"decision,omitempty"`
	Approval     Approval     `json:"approval,omitempty"`
	Installation Installation `json:"installation,omitempty"`
	Verification Verification `json:"verification,omitempty"`
	Rollback     Rollback     `json:"rollback,omitempty"`
	Reason       string       `json:"reason,omitempty"`
}

var defaultPath = defaultAuditPath()

func defaultAuditPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return filepath.Join(".", ".saferun", "audit.jsonl")
	}
	return filepath.Join(homeDir, ".saferun", "audit.jsonl")
}

func SetDefaultPath(path string) {
	defaultPath = path
}

func DefaultPath() string {
	return defaultPath
}

func Clear() error {
	return ClearAt(defaultPath)
}

func ClearAt(path string) error {
	if path == "" {
		path = defaultPath
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove audit log: %w", err)
	}
	return nil
}

type Logger struct {
	Path string
}

func NewLogger() Logger {
	return Logger{Path: defaultPath}
}

func NewLoggerAt(path string) Logger {
	if path == "" {
		return Logger{Path: defaultPath}
	}
	return Logger{Path: path}
}

func (l Logger) Record(event Event) error {
	path := l.Path
	if path == "" {
		path = defaultPath
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if event.Packages == nil {
		event.Packages = []string{}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func ReadRecent(limit int) ([]Event, error) {
	return ReadRecentAt(defaultPath, limit)
}

func ReadRecentAt(path string, limit int) ([]Event, error) {
	events, _, err := ReadRecentWithStats(path, limit)
	return events, err
}

func ReadRecentWithStats(path string, limit int) ([]Event, int, error) {
	if path == "" {
		path = defaultPath
	}
	if limit == 0 {
		limit = 10
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	var events []Event
	var malformed int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			malformed++
			continue
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, malformed, fmt.Errorf("read audit log: %w", err)
	}

	sort.SliceStable(events, func(i, j int) bool {
		t1, t2 := parseTimestamp(events[i].Timestamp), parseTimestamp(events[j].Timestamp)
		if t1.Equal(t2) {
			return false
		}
		return t1.After(t2)
	})

	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, malformed, nil
}

func formatPackageSummary(packages []string) string {
	if len(packages) == 0 {
		return "-"
	}
	summary := strings.Join(packages, ", ")
	if len(summary) <= 32 {
		return summary
	}
	return summary[:29] + "..."
}

func formatRollback(value Rollback) string {
	switch value {
	case RollbackSucceeded:
		return "ROLLBACK: SUCCESS"
	case RollbackFailed:
		return "ROLLBACK: FAILED"
	default:
		return "-"
	}
}

func formatApproval(value Approval) string {
	if value == "" || value == ApprovalNotNeeded {
		return "-"
	}
	return string(value)
}

func formatValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func parseTimestamp(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func FormatRecent(events []Event) string {
	if len(events) == 0 {
		return "(no audit events recorded)"
	}

	head := "TIMESTAMP           | DECISION     | PACKAGE                         | RISK    | INSTALL      | VERIFY       | ROLLBACK           | APPROVAL"
	lines := []string{head, strings.Repeat("-", len(head))}
	for _, event := range events {
		decision := string(event.Decision)
		if decision == "" {
			decision = "UNKNOWN"
		}
		line := fmt.Sprintf("%-19s | %-12s | %-31s | %-7s | %-12s | %-12s | %-18s | %-12s",
			formatTimestamp(event.Timestamp),
			decision,
			formatPackageSummary(event.Packages),
			event.Risk,
			formatValue(string(event.Installation)),
			formatValue(string(event.Verification)),
			formatRollback(event.Rollback),
			formatApproval(event.Approval),
		)
		if event.Reason != "" {
			lines = append(lines, "  reason: "+event.Reason)
		}
		if event.Score > 0 || event.FindingCount > 0 {
			lines = append(lines, fmt.Sprintf("  score: %d | findings: %d", event.Score, event.FindingCount))
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func formatTimestamp(timestamp string) string {
	if timestamp == "" {
		return "unknown"
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return timestamp
	}
	return parsed.Format("2006-01-02 15:04")
}
