package package_manager

import (
	"fmt"
	"os"
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
