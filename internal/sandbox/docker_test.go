package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildDockerArgsSecurityHardening(t *testing.T) {
	workspace := "/tmp/saferun-workspace"
	args := buildDockerArgs(Config{
		Image:     "saferun-node:dev",
		Network:   "bridge",
		Memory:    "512m",
		CPUs:      "1",
		Workspace: workspace,
		PidsLimit: 128,
		Timeout:   5 * time.Minute,
	}, "sh", "-c", "echo ok")

	combined := strings.Join(args, " ")
	for _, want := range []string{
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--memory=512m",
		"--cpus=1",
		"--pids-limit=128",
		"--network=bridge",
		"--read-only",
		"--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
		"--volume=/tmp/saferun-workspace:/saferun/workspace",
		"--workdir=/saferun/workspace",
		"--entrypoint=/bin/sh",
		"saferun-node:dev",
	} {
		if !strings.Contains(combined, want) {
			t.Fatalf("docker args missing %q in %v", want, args)
		}
	}
	if runtime.GOOS != "windows" {
		want := "--user=" + strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
		if !strings.Contains(combined, want) {
			t.Fatalf("docker args missing %q in %v", want, args)
		}
	}

	for _, forbidden := range []string{
		"--privileged",
		"--network=host",
		"/var/run/docker.sock",
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("docker args unexpectedly include %q in %v", forbidden, args)
		}
	}
}

func TestBuildDockerExecArgsPreservesCommandSegments(t *testing.T) {
	got := buildDockerExecArgs("saferun-test", []string{"sh", "-c", "sleep 5"})
	want := []string{"exec", "saferun-test", "sh", "-c", "sleep 5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected docker exec args: got %v want %v", got, want)
	}
}

func TestRunNormalCommandSucceeds(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker runtime unavailable: %v: %s", err, out)
	}

	workspaceRoot := t.TempDir()
	config := Config{
		Image:     "alpine:3.20",
		Network:   "bridge",
		Memory:    "128m",
		CPUs:      "0.5",
		Workspace: workspaceRoot,
		PidsLimit: 128,
		Timeout:   30 * time.Second,
	}
	containersBefore := safeRunContainers(t)

	changes, _, _, err := Run(config, "sh", "-c", "echo ready > /saferun/workspace/test.txt")
	if err != nil {
		t.Fatalf("expected short command to succeed, got: %v", err)
	}
	if len(changes.Created) == 0 {
		t.Fatal("expected created file changes from successful command")
	}
	assertNoNewSafeRunContainers(t, containersBefore)
}

func TestRunTimeout(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker runtime unavailable: %v: %s", err, out)
	}

	workspaceRoot := t.TempDir()
	config := Config{
		Image:     "alpine:3.20",
		Network:   "bridge",
		Memory:    "128m",
		CPUs:      "0.5",
		Workspace: workspaceRoot,
		PidsLimit: 128,
		Timeout:   200 * time.Millisecond,
	}

	_, _, _, err := Run(config, "sh", "-c", "sleep 5")
	if err == nil {
		t.Fatal("expected sandbox timeout error")
	}
	if !strings.Contains(err.Error(), "sandbox timed out") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

func TestRunCreatesIsolatedWorkspaceAndCleansUp(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker runtime unavailable: %v: %s", err, out)
	}

	workspaceRoot := t.TempDir()
	config := Config{
		Image:     "alpine:3.20",
		Network:   "none",
		Memory:    "128m",
		CPUs:      "0.5",
		Workspace: workspaceRoot,
		PidsLimit: 128,
		Timeout:   5 * time.Minute,
	}
	containersBefore := safeRunContainers(t)

	changes, _, _, err := Run(config, "sh", "-c", "echo ready > /saferun/workspace/test.txt && echo hello > /saferun/workspace/hello.txt")
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}
	if len(changes.Created) == 0 {
		t.Fatal("expected filesystem changes from sandbox command")
	}

	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		t.Fatalf("read workspace root: %v", err)
	}
	if len(entries) != 0 {
		files := []string{}
		for _, entry := range entries {
			files = append(files, entry.Name())
		}
		t.Fatalf("expected sandbox workspace to be cleaned up, got leftover entries: %#v", files)
	}

	if _, err := os.Stat(filepath.Join(workspaceRoot, "run-")); err == nil {
		t.Fatal("expected sandbox temp directory to be removed")
	}
	assertNoNewSafeRunContainers(t, containersBefore)
}

func safeRunContainers(t *testing.T) map[string]struct{} {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a", "--filter", "name=saferun-", "--format", "{{.Names}} ").CombinedOutput()
	if err != nil {
		t.Fatalf("list saferun containers: %v: %s", err, out)
	}
	containers := make(map[string]struct{})
	for _, name := range strings.Fields(string(out)) {
		containers[name] = struct{}{}
	}
	return containers
}

func assertNoNewSafeRunContainers(t *testing.T, before map[string]struct{}) {
	t.Helper()
	for name := range safeRunContainers(t) {
		if _, existed := before[name]; !existed {
			t.Fatalf("expected no new leftover saferun containers, got: %q", name)
		}
	}
}
