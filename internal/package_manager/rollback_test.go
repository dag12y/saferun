package package_manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/sandbox"
)

func TestCreateProjectBackupPreservesExistingFile(t *testing.T) {
	projectDir := t.TempDir()
	pkgFile := filepath.Join(projectDir, "package.json")
	if err := os.WriteFile(pkgFile, []byte(`{"name":"demo","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := createProjectBackup(projectDir, nil)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	if backup == nil || backup.BackupDir == "" {
		t.Fatal("expected backup directory")
	}
	if _, err := os.Stat(filepath.Join(backup.BackupDir, "package.json")); err != nil {
		t.Fatalf("expected package.json in backup: %v", err)
	}
	if err := backup.Cleanup(); err != nil {
		t.Fatalf("cleanup backup: %v", err)
	}
}

func TestCreateProjectBackupTracksMissingFile(t *testing.T) {
	projectDir := t.TempDir()
	missingPath := filepath.Join(projectDir, "missing", "file.txt")
	backup, err := createProjectBackup(projectDir, nil)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	defer backup.Cleanup()

	entry, ok := findEntry(backup, missingPath)
	if ok && entry.Existed {
		t.Fatal("missing file should not be marked as existing")
	}
}

func TestProjectBackupRestoreModifiedFile(t *testing.T) {
	projectDir := t.TempDir()
	path := filepath.Join(projectDir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"demo","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := createProjectBackup(projectDir, nil)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"name":"demo","version":"2.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version":"1.0.0"`) {
		t.Fatalf("original package.json not restored: %s", string(data))
	}
}

func TestProjectBackupRestoreDeletedFile(t *testing.T) {
	projectDir := t.TempDir()
	path := filepath.Join(projectDir, "node_modules", "lodash", "package.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"name":"lodash","version":"4.18.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := createProjectBackup(projectDir, []string{"lodash"})
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	if err := os.RemoveAll(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore deleted file: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected package directory to be restored: %v", err)
	}
}

func TestProjectBackupRemovesNewlyCreatedDirectory(t *testing.T) {
	projectDir := t.TempDir()
	backup, err := createProjectBackup(projectDir, []string{"chalk"})
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	newDir := filepath.Join(projectDir, "node_modules", "chalk")
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "package.json"), []byte(`{"name":"chalk","version":"5.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore new dir: %v", err)
	}
	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Fatalf("expected new directory to be removed during restore: %v", err)
	}
}

func TestResolveRequestedPackageScoped(t *testing.T) {
	projectDir := t.TempDir()
	name, version, err := resolveRequestedPackage("@types/node@24.0.0", projectDir)
	if err != nil {
		t.Fatalf("resolveRequestedPackage: %v", err)
	}
	if name != "@types/node" || version != "24.0.0" {
		t.Fatalf("unexpected scope resolution: %s @ %s", name, version)
	}
	if got := filepath.Join(projectDir, "node_modules", name); got == "" {
		t.Fatal("scoped package path unexpectedly empty")
	}
}

func TestCollectBackupTargetsMultiplePackages(t *testing.T) {
	projectDir := t.TempDir()
	paths := collectBackupTargets(projectDir, []string{"lodash", "express"})
	if len(paths) < 3 {
		t.Fatalf("expected package.json and package dirs, got %d: %#v", len(paths), paths)
	}
	if !containsPath(paths, filepath.Join(projectDir, "package.json")) {
		t.Fatal("package.json should be included")
	}
	if !containsPath(paths, filepath.Join(projectDir, "node_modules", "lodash")) {
		t.Fatal("lodash package dir should be included")
	}
	if !containsPath(paths, filepath.Join(projectDir, "node_modules", "express")) {
		t.Fatal("express package dir should be included")
	}
}

func TestProjectBackupCleanupRemovesArtifacts(t *testing.T) {
	projectDir := t.TempDir()
	backup, err := createProjectBackup(projectDir, nil)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	if err := backup.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(backup.BackupDir); !os.IsNotExist(err) {
		t.Fatal("backup directory should be removed after cleanup")
	}
}

func TestNPMInstallRollbackRestoresProjectOnVerificationFailure(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(`{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.18.1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"name":"demo","lockfileVersion":3}`), 0o600); err != nil {
		t.Fatal(err)
	}

	hadPrompt := false
	manager := NPM{
		ProjectDir: projectDir,
		Sandbox:    sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: name, Version: "4.18.1", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
		},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"lodash","version":"4.18.1"}`), 0o600); err != nil {
				return "", err
			}
			return dir, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error {
			if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"name":"demo","lockfileVersion":999}`), 0o600); err != nil {
				return err
			}
			return nil
		},
		Prompt: func(string) bool {
			hadPrompt = true
			return true
		},
	}

	if err := manager.Install([]string{"lodash"}); err == nil {
		t.Fatal("expected verification failure to return an error")
	}
	if !hadPrompt {
		t.Fatal("expected confirmation prompt to be called")
	}
	lockData, err := os.ReadFile(filepath.Join(projectDir, "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lockData), `"lockfileVersion":3`) {
		t.Fatalf("package-lock.json was not restored: %s", string(lockData))
	}
}

func TestProjectBackupRejectsSymlinkTraversal(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	linkPath := filepath.Join(projectDir, "link")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Fatal(err)
	}
	_, err := capturePath(projectDir, filepath.Join(projectDir, ".backup"), linkPath)
	if err == nil {
		t.Fatal("expected symlink traversal to be rejected")
	}
}

func findEntry(backup *ProjectBackup, target string) (backupEntry, bool) {
	for _, entry := range backup.entries {
		if entry.Path == target {
			return entry, true
		}
	}
	return backupEntry{}, false
}

func containsPath(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
	}
	return false
}
