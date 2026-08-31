package package_manager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/risk"
	"github.com/dag12y/saferun/internal/sandbox"
)

func TestNPMInstallMultiplePackagesReportsAllPackages(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "4.18.1", "express": "5.2.1"},
	})
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	for _, pkg := range []struct{ name, version string }{
		{name: "lodash", version: "4.18.1"},
		{name: "express", version: "5.2.1"},
	} {
		path := filepath.Join(projectDir, "node_modules", pkg.name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(fmt.Sprintf(`{"name":"%s","version":"%s"}`, pkg.name, pkg.version)), 0o600); err != nil {
			t.Fatalf("write %s package.json: %v", pkg.name, err)
		}
	}

	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			if name == "lodash" {
				return registry.PackageInfo{Name: "lodash", Version: "4.18.1", TarballURL: "https://example.invalid/lodash.tgz", Integrity: "sha512-lodash"}, nil
			}
			if name == "express" {
				return registry.PackageInfo{Name: "express", Version: "5.2.1", TarballURL: "https://example.invalid/express.tgz", Integrity: "sha512-express"}, nil
			}
			return registry.PackageInfo{Name: name}, nil
		},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/package.json", []byte(fmt.Sprintf(`{"name":"%s","version":"%s"}`, pkg.Name, pkg.Version)), 0o600); err != nil {
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

	if err := manager.Install([]string{"lodash", "express"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
}

func TestRiskAnalyzeAggregatesFindingsAcrossPackages(t *testing.T) {
	findings := []risk.Finding{
		{Name: "lodash", Description: "minor script", Severity: risk.Low},
		{Name: "express", Description: "unexpected external connection", Severity: risk.Medium},
	}

	report := risk.Analyze(findings)
	if report.Score != 6 {
		t.Fatalf("expected aggregate score 6, got %d", report.Score)
	}
	if report.Level != risk.Medium {
		t.Fatalf("expected MEDIUM, got %s", report.Level)
	}
}

func TestNPMInstallApprovalAfterAnalysis(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "1.0.0", "express": "1.0.0"},
	})
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	for _, pkg := range []struct{ name, version string }{
		{name: "lodash", version: "1.0.0"},
		{name: "express", version: "1.0.0"},
	} {
		path := filepath.Join(projectDir, "node_modules", pkg.name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(fmt.Sprintf(`{"name":"%s","version":"%s"}`, pkg.name, pkg.version)), 0o600); err != nil {
			t.Fatalf("write %s package.json: %v", pkg.name, err)
		}
	}

	promptCalled := false
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: name, Version: "1.0.0", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
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
		RealInstaller: func(args []string) error { return nil },
		Prompt: func(string) bool {
			promptCalled = true
			return true
		},
	}

	if err := manager.Install([]string{"lodash", "express"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if !promptCalled {
		t.Fatal("expected prompt to be called after all package analysis")
	}
}

func TestNPMInstallPreservesOriginalArguments(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "1.0.0", "express": "1.0.0"},
	})
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })
	for _, pkg := range []struct{ name, version string }{
		{name: "lodash", version: "1.0.0"},
		{name: "express", version: "1.0.0"},
	} {
		path := filepath.Join(projectDir, "node_modules", pkg.name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("MkdirAll %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(path, "package.json"), []byte(fmt.Sprintf(`{"name":"%s","version":"%s"}`, pkg.name, pkg.version)), 0o600); err != nil {
			t.Fatalf("write %s package.json: %v", pkg.name, err)
		}
	}

	installerArgs := []string(nil)
	manager := NPM{
		Sandbox: sandbox.Config{Workspace: t.TempDir()},
		ResolveFunc: func(name string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: name, Version: "1.0.0", TarballURL: "https://example.invalid/package.tgz", Integrity: "sha512-test"}, nil
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
		Prompt: func(string) bool { return true },
	}

	if err := manager.Install([]string{"lodash", "express", "--save"}); err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if !strings.Contains(strings.Join(installerArgs, " "), "lodash express --save") {
		t.Fatalf("expected original npm args preserved, got %#v", installerArgs)
	}
}
