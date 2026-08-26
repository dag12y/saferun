package sandbox

import (
	"fmt"
	"os/exec"
)

func Run(command ...string) error {
	args := []string{
		"run",
		"--rm",
		"saferun-node:dev",
	}

	args = append(args, command...)

	cmd := exec.Command("docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sandbox failed: %w\n%s", err, output)
	}

	fmt.Print(string(output))
	return nil
}