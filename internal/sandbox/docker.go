package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

	before, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, err
	}

	containerName := "saferun-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	args := []string{
		"run",
		"-d",

		"--name",
		containerName,

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

		// Match host user permissions
		"--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),

		// Bypass image entrypoint
		"--entrypoint=/bin/sh",

		config.Image,

		"-c",
		"tail -f /dev/null",
	}

	// Start container.
	startCmd := exec.Command("docker", args...)

	output, err := startCmd.CombinedOutput()
	if err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"sandbox failed to start: %w\n%s",
			err,
			output,
		)
	}

	// Always remove the container when we're finished.
	defer func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	fmt.Println("Sandbox started:", containerName)

	// Run package manager command inside the running sandbox.
	commandString := strings.Join(command, " ")

	installCmd := exec.Command(
		"docker",
		"exec",
		containerName,
		"sh",
		"-c",
		commandString,
	)

	installOutput, err := installCmd.CombinedOutput()

	fmt.Print(string(installOutput))

	if err != nil {
		return analyzer.FileChanges{}, fmt.Errorf(
			"sandbox install failed: %w",
			err,
		)
	}

	after, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, err
	}

	changes := analyzer.CompareSnapshots(before, after)

	return changes, nil
}
