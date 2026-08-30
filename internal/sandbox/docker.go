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

func Run(config Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, error) {
	parent := config.Workspace

	if parent == "" {
		return analyzer.FileChanges{}, nil, fmt.Errorf("sandbox workspace is required")
	}

	if err := os.MkdirAll(parent, 0755); err != nil {
		return analyzer.FileChanges{}, nil, fmt.Errorf(
			"create sandbox workspace parent: %w",
			err,
		)
	}

	workspace, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return analyzer.FileChanges{}, nil, fmt.Errorf(
			"create sandbox workspace: %w",
			err,
		)
	}

	defer os.RemoveAll(workspace)

	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, fmt.Errorf(
			"resolve sandbox workspace: %w",
			err,
		)
	}

	before, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, err
	}

	containerName := "saferun-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	args := []string{
		"run",
		"-d",
		"--name",
		containerName,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--memory=" + config.Memory,
		"--cpus=" + config.CPUs,
		"--network=" + config.Network,
		"--volume=" + workspace + ":/saferun/workspace",
		"--workdir=/saferun/workspace",
		"--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"--entrypoint=/bin/sh",
		config.Image,
		"-c",
		"tail -f /dev/null",
	}

	startCmd := exec.Command("docker", args...)
	output, err := startCmd.CombinedOutput()
	if err != nil {
		return analyzer.FileChanges{}, nil, fmt.Errorf(
			"sandbox failed to start: %w\n%s",
			err,
			output,
		)
	}

	defer func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	fmt.Println("Sandbox started:", containerName)

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
		return analyzer.FileChanges{}, nil, fmt.Errorf("sandbox installation failed: %w", err)
	}

	processFindings, err := analyzer.AnalyzeProcesses(containerName)
	if err != nil {
		return analyzer.FileChanges{}, nil, fmt.Errorf("sandbox process analysis failed: %w", err)
	}

	after, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, err
	}

	changes := analyzer.CompareSnapshots(before, after)
	return changes, processFindings, nil
}
