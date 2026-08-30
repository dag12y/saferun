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

func Run(config Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
	parent := config.Workspace

	if parent == "" {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox workspace is required")
	}

	if err := os.MkdirAll(parent, 0755); err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf(
			"create sandbox workspace parent: %w",
			err,
		)
	}

	workspace, err := os.MkdirTemp(parent, "run-")
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf(
			"create sandbox workspace: %w",
			err,
		)
	}

	defer os.RemoveAll(workspace)

	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf(
			"resolve sandbox workspace: %w",
			err,
		)
	}

	before, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, err
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
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf(
			"sandbox failed to start: %w\n%s",
			err,
			output,
		)
	}

	defer func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	fmt.Println("Sandbox started:", containerName)

	monitorCmd := exec.Command(
		"docker",
		"exec",
		containerName,
		"sh",
		"-c",
		`rm -f /tmp/saferun-network.log; while true; do { cat /proc/net/tcp 2>/dev/null; echo '---'; cat /proc/net/tcp6 2>/dev/null; } >> /tmp/saferun-network.log; sleep 0.5; done & echo $! >/tmp/saferun-network.pid`,
	)
	if output, err := monitorCmd.CombinedOutput(); err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("start sandbox network monitor: %w: %s", err, string(output))
	}

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
		stopMonitor := exec.Command("docker", "exec", containerName, "sh", "-c", "kill $(cat /tmp/saferun-network.pid) 2>/dev/null || true")
		_ = stopMonitor.Run()
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox installation failed: %w", err)
	}

	stopMonitor := exec.Command("docker", "exec", containerName, "sh", "-c", "kill $(cat /tmp/saferun-network.pid) 2>/dev/null || true")
	if out, err := stopMonitor.CombinedOutput(); err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("stop sandbox network monitor: %w: %s", err, string(out))
	}

	processFindings, err := analyzer.AnalyzeProcesses(containerName)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox process analysis failed: %w", err)
	}

	networkConnections, err := analyzer.CollectNetworkConnections(containerName)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox network analysis failed: %w", err)
	}

	after, err := analyzer.SnapshotDirectory(workspace)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, err
	}

	changes := analyzer.CompareSnapshots(before, after)
	return changes, processFindings, networkConnections, nil
}
