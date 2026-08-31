package sandbox

import (
	"fmt"
	"io"
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

	command, err = prepareLocalPackageInSandbox(workspace, command)
	if err != nil {
		return analyzer.FileChanges{}, nil, nil, err
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

func prepareLocalPackageInSandbox(workspace string, command []string) ([]string, error) {
	updated := append([]string(nil), command...)
	for i := 0; i < len(updated)-1; i++ {
		if updated[i] != "install" {
			continue
		}
		packageSpec := updated[i+1]
		if packageSpec == "" || !looksLikeLocalPath(packageSpec) {
			continue
		}

		absPath, err := filepath.Abs(packageSpec)
		if err != nil {
			return nil, fmt.Errorf("resolve local package path %q: %w", packageSpec, err)
		}

		packageName := filepath.Base(absPath)
		destination := filepath.Join(workspace, packageName)
		if err := copyLocalPackage(absPath, destination); err != nil {
			return nil, fmt.Errorf("copy local package %q to sandbox workspace: %w", packageSpec, err)
		}

		updated[i+1] = filepath.ToSlash(filepath.Join("/saferun/workspace", packageName))
	}
	return updated, nil
}

func looksLikeLocalPath(spec string) bool {
	if spec == "" {
		return false
	}
	return filepath.IsAbs(spec) || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "~") || strings.HasPrefix(spec, "..")
}

func copyLocalPackage(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDirectory(src, dst)
	}
	return copyFile(src, dst)
}

func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			return err
		}
		return nil
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
