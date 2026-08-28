package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dag12y/saferun/internal/analyzer"
)

func Run(config Config, command ...string) (analyzer.FileChanges, error) {
	parent := config.Workspace

	if parent == "" {
		return analyzer.FileChanges{}, fmt.Errorf("sandbox workspace is required")
	}

	if err := os.MkdirAll(parent, 0755); err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"create sandbox workspace parent: %w",
			err,
		)
	}

	workspace, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"create sandbox workspace: %w",
			err,
		)
	}

	defer os.RemoveAll(workspace)

	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"resolve sandbox workspace: %w",
			err,
		)
	}

	// Snapshot before installation
	before, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, err
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

		// Workspace
		"--volume=" + workspace + ":/saferun/workspace",
		"--workdir=/saferun/workspace",

		// Match host user permissions
		"--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),

		// Bypass node entrypoint
		"--entrypoint=/bin/sh",

		config.Image,
	}

	commandString := strings.Join(command, " ")

	args = append(args, "-c", commandString)

	cmd := exec.Command("docker", args...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"sandbox failed: %w\n%s",
			err,
			output,
		)
	}

	fmt.Print(string(output))

	// Snapshot after installation
	after, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, err
	}

	changes := analyzer.CompareSnapshots(before, after)

	return changes, nil
}
