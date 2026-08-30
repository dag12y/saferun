package analyzer

import (
	"bufio"
	"fmt"
	"os/exec"
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
		"ps",
		"-eo",
		"comm,args",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect sandbox processes: %w", err)
	}

	var findings []ProcessFinding

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		command := fields[0]

		switch command {
		case "curl", "wget":
			findings = append(findings, ProcessFinding{
				Command:  line,
				Severity: "HIGH",
				Reason:   "Network download utility executed",
			})

		case "sh", "bash":
			findings = append(findings, ProcessFinding{
				Command:  line,
				Severity: "MEDIUM",
				Reason:   "Shell process executed",
			})
		}
	}

	return findings, scanner.Err()
}
