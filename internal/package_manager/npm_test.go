package package_manager

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/sandbox"
)

type fakeRegistry struct{}

func (fakeRegistry) Resolve(name string) (registry.PackageInfo, error) {
	return registry.PackageInfo{
		Name:       name,
		Version:    "4.17.0",
		TarballURL: "https://example.invalid/package.tgz",
		Integrity:  "sha512-test",
	}, nil
}

func (fakeRegistry) Download(pkg registry.PackageInfo) (string, error) {
	dir := os.TempDir() + "/saferun-fake-package"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dir+"/package.json", []byte(`{"name":"test","version":"1.0.0"}`), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

func TestNPMInstallCancelledDoesNotRunRealInstall(t *testing.T) {
	installerCalled := false
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: name, Version: "4.17.0", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
		},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/package.json", []byte(`{"name":"test","version":"1.0.0"}`), 0o600); err != nil {
				return "", err
			}
			return dir, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error {
			installerCalled = true
			return nil
		},
		Prompt: func(msg string) bool {
			return false
		},
	}

	if err := manager.Install([]string{"lodash"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if installerCalled {
		t.Fatal("real install should not run when user declines")
	}
}

func TestNPMInstallApprovedInvokesRealInstall(t *testing.T) {
	installerArgs := []string(nil)
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: name, Version: "4.17.0", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
		},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/package.json", []byte(`{"name":"test","version":"1.0.0"}`), 0o600); err != nil {
				return "", err
			}
			return dir, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error {
			installerArgs = append([]string(nil), args...)
			return nil
		},
		Prompt: func(msg string) bool {
			return true
		},
	}

	if err := manager.Install([]string{"lodash", "--save"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if len(installerArgs) == 0 || installerArgs[0] != "install" {
		t.Fatalf("expected install command, got %#v", installerArgs)
	}
	if fmt.Sprintf("%v", installerArgs) != "[install lodash --save]" {
		t.Fatalf("expected preserved npm args, got %#v", installerArgs)
	}
}

func TestNPMInstallRegistryPackageStillResolvesNormally(t *testing.T) {
	called := false
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			called = true
			return registry.PackageInfo{Name: name, Version: "4.17.0", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
		},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/package.json", []byte(`{"name":"lodash","version":"4.17.0"}`), 0o600); err != nil {
				return "", err
			}
			return dir, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error { return nil },
		Prompt:        func(string) bool { return false },
	}

	if err := manager.Install([]string{"lodash"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected registry resolver to be called for registry packages")
	}
}

func TestNPMInstallRelativeLocalPackagePath(t *testing.T) {
	packageDir := t.TempDir()
	if err := os.WriteFile(packageDir+"/package.json", []byte(`{"name":"saferun-suspicious-test","version":"1.0.0","scripts":{"postinstall":"node malicious.js"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Dir(packageDir)); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	called := false
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			called = true
			return registry.PackageInfo{Name: name}, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error { return nil },
		Prompt:        func(string) bool { return false },
	}

	relative := "." + string(os.PathSeparator) + filepath.Base(packageDir)
	if err := manager.Install([]string{relative}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if called {
		t.Fatal("registry resolver should not be called for local package paths")
	}
}

func TestNPMInstallAbsoluteLocalPackagePath(t *testing.T) {
	packageDir := t.TempDir()
	if err := os.WriteFile(packageDir+"/package.json", []byte(`{"name":"saferun-suspicious-test","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	called := false
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			called = true
			return registry.PackageInfo{Name: name}, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error { return nil },
		Prompt:        func(string) bool { return false },
	}

	if err := manager.Install([]string{packageDir}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if called {
		t.Fatal("registry resolver should not be called for absolute local package paths")
	}
}

func TestNPMInstallLocalPackageMissingPathReturnsUsefulError(t *testing.T) {
	manager := NPM{Sandbox: sandbox.Config{Workspace: t.TempDir()}}
	if err := manager.Install([]string{"/definitely/not/here"}); err == nil {
		t.Fatal("expected missing local package path to return an error")
	}
}

func TestNPMInstallLocalPackageMissingPackageJSONReturnsUsefulError(t *testing.T) {
	packageDir := t.TempDir()
	manager := NPM{Sandbox: sandbox.Config{Workspace: t.TempDir()}}
	if err := manager.Install([]string{packageDir}); err == nil {
		t.Fatal("expected local package without package.json to return an error")
	}
}

func TestNPMInstallLocalPackageDoesNotCallRegistryResolver(t *testing.T) {
	packageDir := t.TempDir()
	if err := os.WriteFile(packageDir+"/package.json", []byte(`{"name":"saferun-suspicious-test","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			t.Fatalf("registry resolver should not be called for local package path %q", name)
			return registry.PackageInfo{}, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, nil, nil
		},
		RealInstaller: func(args []string) error { return nil },
		Prompt:        func(string) bool { return false },
	}

	if err := manager.Install([]string{packageDir}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
}
