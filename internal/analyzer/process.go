package analyzer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessFinding struct {
	Command  string
	Severity string
	Reason   string
}

func AnalyzeProcesses(containerID string) ([]ProcessFinding, error) {
	cmd := exec.Command(
		"docker",
		"exec",
		containerID,
		"sh",
		"-c",
		`for proc in /proc/[0-9]*/cmdline; do [ -r "$proc" ] || continue; tr '\0' ' ' < "$proc"; echo; done`,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("inspect sandbox processes: %w", err)
	}

	return AnalyzeProcessOutput(string(output)), nil
}

func AnalyzeProcRoot(root string) ([]ProcessFinding, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}

	var lines []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		cmdlinePath := filepath.Join(root, entry.Name(), "cmdline")
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		if len(data) == 0 {
			continue
		}

		line := strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
		if line != "" {
			lines = append(lines, line)
		}
	}

	return AnalyzeProcessOutput(strings.Join(lines, "\n")), nil
}

func AnalyzeProcessOutput(output string) []ProcessFinding {
	var findings []ProcessFinding

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cmdName := firstCommandName(line)
		if cmdName == "" {
			continue
		}

		lowerLine := strings.ToLower(line)
		lowerName := strings.ToLower(cmdName)

		switch lowerName {
		case "curl", "wget", "nc", "netcat":
			findings = append(findings, ProcessFinding{
				Command:  cmdName,
				Severity: "HIGH",
				Reason:   "Network download utility executed",
			})
		case "bash":
			if strings.Contains(lowerLine, "curl") ||
				strings.Contains(lowerLine, "wget") ||
				strings.Contains(lowerLine, "nc ") ||
				strings.Contains(lowerLine, "netcat") ||
				strings.Contains(lowerLine, "bash -c") {
				findings = append(findings, ProcessFinding{
					Command:  cmdName,
					Severity: "MEDIUM",
					Reason:   "Shell process executed suspicious payload",
				})
			}
		}
	}

	return findings
}

func firstCommandName(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return filepath.Base(fields[0])
}
