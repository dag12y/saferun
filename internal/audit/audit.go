package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Decision string

type Approval string

type Installation string

type Verification string

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
	if limit <= 0 {
		limit = 20
	}
	if path == "" {
		path = defaultPath
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
		if len(events) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return events, nil
}

func FormatRecent(events []Event) string {
	if len(events) == 0 {
		return "(no audit events recorded)"
	}
	var lines []string
	for _, event := range events {
		packageSummary := "unknown"
		if len(event.Packages) > 0 {
			packageSummary = strings.Join(event.Packages, ", ")
		}
		decision := string(event.Decision)
		if decision == "" {
			decision = "UNKNOWN"
		}
		line := fmt.Sprintf("%-18s  %-16s  %-18s  %-8s  %-12s",
			decision,
			formatTimestamp(event.Timestamp),
			packageSummary,
			event.Risk,
			event.Installation,
		)
		if event.Approval != "" {
			line = fmt.Sprintf("%s  %s", line, event.Approval)
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
