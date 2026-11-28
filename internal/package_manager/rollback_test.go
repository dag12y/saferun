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

	backup, err := createProjectBackup(projectDir)
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
	backup, err := createProjectBackup(projectDir)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	defer backup.Cleanup()

	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		path := filepath.Join(backup.ProjectDir, name)
		entry, ok := findEntry(backup, path)
		if !ok || entry.Existed {
			t.Fatalf("backup did not record %s as absent", name)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		if _, err := os.Stat(filepath.Join(projectDir, name)); !os.IsNotExist(err) {
			t.Fatalf("newly created %s survived rollback: %v", name, err)
		}
	}
}

func TestProjectBackupRestoreModifiedFile(t *testing.T) {
	projectDir := t.TempDir()
	path := filepath.Join(projectDir, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"demo","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := createProjectBackup(projectDir)
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

	backup, err := createProjectBackup(projectDir)
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
	backup, err := createProjectBackup(projectDir)
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

func TestProjectBackupCleanupRemovesArtifacts(t *testing.T) {
	projectDir := t.TempDir()
	backup, err := createProjectBackup(projectDir)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	backupDir := backup.BackupDir
	if err := backup.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
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
		preparePlan: unplannedFixtureInstall,
		ProjectDir:  projectDir,
		Sandbox:     sandbox.Config{Workspace: t.TempDir()},
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

func TestProjectBackupRestoreRejectsOutsideProjectPath(t *testing.T) {
	projectDir := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "escape.txt")
	if err := os.WriteFile(outsideFile, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	backup := &ProjectBackup{
		ProjectDir: projectDir,
		BackupDir:  t.TempDir(),
		entries: []backupEntry{
			{
				Path:    outsideFile,
				Existed: false,
			},
		},
	}

	if err := backup.Restore(); err == nil {
		t.Fatal("expected restore to reject path outside project root")
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("expected outside file to remain untouched: %v", err)
	}
}

func TestProjectBackupRemovesTransitiveDependenciesWhenNodeModulesCreated(t *testing.T) {
	projectDir := t.TempDir()
	backup, err := createProjectBackup(projectDir)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}

	for _, rel := range []string{
		filepath.Join("node_modules", "lodash", "package.json"),
		filepath.Join("node_modules", "transitive-dep", "package.json"),
		filepath.Join("node_modules", "@scope", "nested-dep", "package.json"),
	} {
		full := filepath.Join(projectDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(`{"name":"pkg","version":"1.0.0"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := backup.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(projectDir, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("expected newly created node_modules to be completely removed, got %v", err)
	}
}

func TestProjectBackupPrunesNewTransitiveDependenciesPreservingExisting(t *testing.T) {
	projectDir := t.TempDir()
	const original = `{"name":"keep","version":"1.0.0"}`
	changed := filepath.Join(projectDir, "node_modules", "existing-pkg", "package.json")
	deleted := filepath.Join(projectDir, "node_modules", "@org", "keep", "package.json")
	for _, full := range []string{changed, deleted} {
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	backup, err := createProjectBackup(projectDir)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	if err := os.WriteFile(changed, []byte(`{"name":"keep","version":"2.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{
		filepath.Join("node_modules", "lodash", "package.json"),
		filepath.Join("node_modules", "transitive-dep", "package.json"),
		filepath.Join("node_modules", "@org", "new-dep", "package.json"),
		filepath.Join("node_modules", "@newscope", "extra", "package.json"),
	} {
		full := filepath.Join(projectDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(`{"name":"added","version":"1.0.0"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := backup.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	for _, keep := range []string{changed, deleted} {
		data, err := os.ReadFile(keep)
		if err != nil || string(data) != original {
			t.Fatalf("expected existing package %s to be restored: data=%q error=%v", keep, data, err)
		}
	}
	for _, removed := range []string{
		filepath.Join(projectDir, "node_modules", "lodash"),
		filepath.Join(projectDir, "node_modules", "transitive-dep"),
		filepath.Join(projectDir, "node_modules", "@org", "new-dep"),
		filepath.Join(projectDir, "node_modules", "@newscope"),
	} {
		if _, err := os.Stat(removed); !os.IsNotExist(err) {
			t.Fatalf("expected added dependency %s to be removed, got %v", removed, err)
		}
	}
}

func TestProjectBackupRestoresNodeModulesBinLink(t *testing.T) {
	projectDir := t.TempDir()
	nodeModules := filepath.Join(projectDir, "node_modules")
	link := filepath.Join(nodeModules, ".bin", "example")
	dst := filepath.Join("..", "example", "cli.js")
	for _, dir := range []string{filepath.Dir(link), filepath.Join(nodeModules, "example")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "example", "cli.js"), []byte("original"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dst, link); err != nil {
		t.Fatal(err)
	}

	backup, err := createProjectBackup(projectDir)
	if err != nil {
		t.Fatalf("createProjectBackup: %v", err)
	}
	defer backup.Cleanup()

	// A replacement link must be removed as a link during rollback.
	newTarget := t.TempDir()
	if err := os.WriteFile(filepath.Join(newTarget, "sentinel"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(nodeModules); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(newTarget, nodeModules); err != nil {
		t.Fatal(err)
	}
	if err := backup.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != dst {
		t.Fatalf("restored .bin link = %q, %v; want %q", got, err, dst)
	}
	if contents, err := os.ReadFile(link); err != nil || string(contents) != "original" {
		t.Fatalf("restored .bin contents = %q, %v", contents, err)
	}
	if _, err := os.Stat(filepath.Join(newTarget, "sentinel")); err != nil {
		t.Fatalf("replacement link target was modified: %v", err)
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
