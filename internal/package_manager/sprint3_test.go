package package_manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/audit"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/report"
	"github.com/dag12y/saferun/internal/risk"
	"github.com/dag12y/saferun/internal/sandbox"
)

func TestNPMInstallRespectsSaferunrcAndSARIF(t *testing.T) {
	t.Setenv("SAFERUN_CONFIG", "")
	projectDir := t.TempDir()
	localPkgDir := filepath.Join(t.TempDir(), "demo-pkg")
	if err := os.MkdirAll(localPkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localPkgDir, "package.json"), []byte(`{"name":"demo-pkg","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	rc := `{
		"network": {"allowed_hosts": ["cdn.example.internal"]},
		"policy": {"block_on_medium": true}
	}`
	if err := os.WriteFile(filepath.Join(projectDir, ".saferunrc"), []byte(rc), 0o600); err != nil {
		t.Fatal(err)
	}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	manager := NPM{
		ProjectDir:  projectDir,
		AuditLogger: stubAuditLogger(t),
		Format:      "sarif",
		SandboxRunner: func(cfg sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, []analyzer.NetworkConnection{
				{Process: "node", Destination: "cdn.example.internal", Port: 443},
			}, nil
		},
		CheckVulnsFunc: func(name, version string) ([]risk.Finding, error) {
			return []risk.Finding{
				{Name: name + "@" + version + " (GHSA-test)", Description: "Test vuln", Severity: risk.High},
			}, nil
		},
		RealInstaller: func([]string) error {
			t.Fatal("real installer should not run when blocked")
			return nil
		},
	}

	installErr := manager.Install([]string{localPkgDir})
	_ = w.Close()
	os.Stdout = origStdout

	if installErr == nil {
		t.Fatal("expected policy block error due to high vulnerability finding")
	}

	var sarif report.SARIFReport
	if err := json.NewDecoder(r).Decode(&sarif); err != nil {
		t.Fatalf("decode SARIF output: %v", err)
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF report: %#v", sarif)
	}
}

func TestNPMInstallSaferunrcAllowsHost(t *testing.T) {
	t.Setenv("SAFERUN_CONFIG", "")
	projectDir := t.TempDir()
	localPkgDir := filepath.Join(t.TempDir(), "clean-pkg")
	if err := os.MkdirAll(localPkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localPkgDir, "package.json"), []byte(`{"name":"clean-pkg","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".saferunrc"), []byte(`{"network":{"allowed_hosts":["registry.internal.corp"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	installed := false
	manager := NPM{
		ProjectDir:  projectDir,
		AuditLogger: stubAuditLogger(t),
		JSON:        true,
		SandboxRunner: func(cfg sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			return analyzer.FileChanges{}, nil, []analyzer.NetworkConnection{
				{Process: "node", Destination: "registry.internal.corp", Port: 443},
			}, nil
		},
		ResolveFunc: func(s string) (registry.PackageInfo, error) {
			return registry.PackageInfo{Name: "clean-pkg", Version: "1.0.0"}, nil
		},
		Prompt: func(string) bool { return true },
		RealInstaller: func([]string) error {
			installed = true
			return nil
		},
	}

	if err := manager.Install([]string{localPkgDir}); err != nil {
		t.Fatalf("expected allowed_hosts to permit install, got: %v", err)
	}
	if installed {
		t.Fatal("JSON mode only outputs report without host install")
	}
}

func stubAuditLogger(t *testing.T) audit.Logger {
	t.Helper()
	return audit.Logger{Path: filepath.Join(t.TempDir(), "audit.jsonl")}
}
