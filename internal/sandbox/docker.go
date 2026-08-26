package sandbox

import (
	"fmt"
	"os/exec"
)

func Run(config Config, command ...string) error {
	args := []string{
		"run",
		"--rm",

		// Security
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",

		// Resource limits
		"--memory=" + config.Memory,
		"--cpus=" + config.CPUs,

		// Network
		"--network=" + config.Network,

		config.Image,
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
