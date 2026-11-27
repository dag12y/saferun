package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dag12y/saferun/internal/analyzer"
)

func Run(config Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Minute
	}
	if config.PidsLimit <= 0 {
		config.PidsLimit = 128
	}

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
	config.Workspace = workspace
	if config.ProjectDir != "" {
		if err := copyProjectDirectory(config.ProjectDir, workspace); err != nil {
			return analyzer.FileChanges{}, nil, nil, fmt.Errorf("stage project in sandbox: %w", err)
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	args := buildDockerArgs(config, "infinity")
	args = append([]string{"run", "-d", "--name", containerName, "--rm"}, args...)
	startCmd := exec.CommandContext(ctx, "docker", args...)
	output, err := startCmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox timed out after %s", config.Timeout)
		}
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf(
			"sandbox failed to start: %w\n%s",
			err,
			output,
		)
	}

	defer func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	reportOutput := config.Output
	if reportOutput == nil {
		reportOutput = os.Stdout
	}
	fmt.Fprintln(reportOutput, "Sandbox started:", containerName)

	monitorCmd := exec.Command(
		"docker",
		"exec",
		containerName,
		"sh",
		"-c",
		`rm -f /tmp/saferun-network.log /tmp/saferun-process.log; while true; do { cat /proc/net/tcp 2>/dev/null; echo '---'; cat /proc/net/tcp6 2>/dev/null; } >> /tmp/saferun-network.log; for proc in /proc/[0-9]*/cmdline; do [ -r "$proc" ] || continue; tr '\0' ' ' < "$proc"; echo; done >> /tmp/saferun-process.log 2>/dev/null; sleep 0.1; done & echo $! >/tmp/saferun-network.pid`,
	)
	if output, err := monitorCmd.CombinedOutput(); err != nil {
		return analyzer.FileChanges{}, nil, nil, fmt.Errorf("start sandbox network monitor: %w: %s", err, string(output))
	}

	installCtx, installCancel := context.WithTimeout(context.Background(), config.Timeout)
	defer installCancel()
	installArgs := buildDockerExecArgs(containerName, command)
	installCmd := exec.CommandContext(installCtx, "docker", installArgs...)
	installOutput, err := installCmd.CombinedOutput()
	fmt.Fprint(reportOutput, string(installOutput))
	if err != nil {
		if installCtx.Err() == context.DeadlineExceeded {
			return analyzer.FileChanges{}, nil, nil, fmt.Errorf("sandbox timed out after %s", config.Timeout)
		}
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

func buildDockerArgs(config Config, command ...string) []string {
	workspace := config.Workspace
	if workspace == "" {
		workspace = "/saferun/workspace"
	}
	if config.PidsLimit <= 0 {
		config.PidsLimit = 128
	}
	args := []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--memory=" + config.Memory,
		"--cpus=" + config.CPUs,
		"--pids-limit=" + strconv.Itoa(config.PidsLimit),
		"--network=" + config.Network,
		"--read-only",
		"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
		"--env=HOME=/tmp",
		"--env=NPM_CONFIG_CACHE=/tmp/.npm",
		"--env=TMPDIR=/tmp",
		"--volume=" + workspace + ":/saferun/workspace",
		"--workdir=/saferun/workspace",
	}
	if runtime.GOOS != "windows" {
		args = append(args, "--user="+strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid()))
	}
	args = append(args, "--entrypoint=sleep", config.Image)
	args = append(args, command...)
	return args
}

func buildDockerExecArgs(containerName string, command []string) []string {
	args := append([]string{"exec", containerName}, command...)
	return args
}

func prepareLocalPackageInSandbox(workspace string, command []string) ([]string, error) {
	updated := append([]string(nil), command...)
	installIdx := -1
	for i, arg := range updated {
		if arg == "install" {
			installIdx = i
			break
		}
	}
	if installIdx == -1 {
		return updated, nil
	}

	for i := installIdx + 1; i < len(updated); i++ {
		packageSpec := updated[i]
		if packageSpec == "" || strings.HasPrefix(packageSpec, "-") || !looksLikeLocalPath(packageSpec) {
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

		updated[i] = filepath.ToSlash(filepath.Join("/saferun/workspace", packageName))
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
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %q", path)
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

func copyProjectDirectory(src, dst string) error {
	root, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if relative == "node_modules" || strings.HasPrefix(relative, "node_modules"+string(os.PathSeparator)) || relative == ".git" || strings.HasPrefix(relative, ".git"+string(os.PathSeparator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(relative)
		if base == ".npmrc" || base == ".yarnrc" || base == ".yarnrc.yml" || base == ".env" || strings.HasPrefix(base, ".env.") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is not supported", relative)
		}
		target := filepath.Join(dst, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
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
