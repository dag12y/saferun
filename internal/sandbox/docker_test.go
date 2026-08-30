package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunCreatesIsolatedWorkspaceAndCleansUp(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	workspaceRoot := t.TempDir()
	config := Config{
		Image:     "alpine:3.20",
		Network:   "none",
		Memory:    "128m",
		CPUs:      "0.5",
		Workspace: workspaceRoot,
	}

	changes, _, err := Run(config, "sh", "-c", "echo ready > /saferun/workspace/test.txt && echo hello > /saferun/workspace/hello.txt")
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
}
