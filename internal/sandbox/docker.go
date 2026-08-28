package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func Run(config Config, command ...string) error {
	parent := config.Workspace
	if parent == "" {
		return fmt.Errorf("sandbox workspace is required")
	}

	if err := os.MkdirAll(parent, 0755); err != nil {
		return fmt.Errorf("create sandbox workspace parent: %w", err)
	}

	workspace, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return fmt.Errorf("create sandbox workspace: %w", err)
	}
	defer os.RemoveAll(workspace)

	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return fmt.Errorf("resolve sandbox workspace: %w", err)
	}

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

		// Isolated workspace
		"--volume=" + workspace + ":/saferun/workspace",
		"--workdir=/saferun/workspace",

		// Match the host user so npm can write to the bind-mounted workspace.
		// With --cap-drop=ALL, root cannot bypass directory ownership checks.
		"--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),

		// Bypass the image entrypoint.
		"--entrypoint=/bin/sh",

		config.Image,
	}

	commandString := strings.Join(command, " ")

	args = append(args, "-c", commandString)

	cmd := exec.Command("docker", args...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("sandbox failed: %w\n%s", err, output)
	}

	fmt.Print(string(output))

	return nil
}
