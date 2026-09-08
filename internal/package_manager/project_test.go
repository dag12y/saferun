package package_manager

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/sandbox"
)

func TestResolveProjectReadsLockfilePackages(t *testing.T) {
	dir := t.TempDir()
	writeProjectJSON(t, filepath.Join(dir, "package.json"), map[string]any{
		"name":            "fixture-app",
		"dependencies":    map[string]string{"lodash": "^4.17.0"},
		"devDependencies": map[string]string{"jest": "^29.0.0"},
	})
	writeProjectJSON(t, filepath.Join(dir, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^4.17.0"}, "devDependencies": map[string]string{"jest": "^29.0.0"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": testIntegrity()},
			"node_modules/jest":   map[string]any{"version": "29.7.0", "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz", "integrity": testIntegrity()},
		},
	})

	resolution, err := resolveProject(dir, nil)
	if err != nil {
		t.Fatalf("resolveProject returned error: %v", err)
	}
	if len(resolution.Dependencies) != 2 || len(resolution.Packages) != 2 {
		t.Fatalf("unexpected resolution: %#v", resolution)
	}
	if resolution.Packages[0].Name != "jest" || resolution.Packages[1].Name != "lodash" {
		t.Fatalf("expected deterministic package ordering, got %#v", resolution.Packages)
	}
}

func TestResolveProjectRejectsUnsupportedDependency(t *testing.T) {
	dir := t.TempDir()
	writeProjectJSON(t, filepath.Join(dir, "package.json"), map[string]any{
		"name":         "fixture-app",
		"dependencies": map[string]string{"local-package": "file:../local-package"},
	})
	if _, err := resolveProject(dir, nil); err == nil {
		t.Fatal("expected unsupported dependency to fail closed")
	}
}

func TestNPMInstallProjectJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeProjectJSON(t, filepath.Join(dir, "package.json"), map[string]any{
		"name":         "fixture-app",
		"dependencies": map[string]string{"lodash": "^4.17.0"},
	})
	writeProjectJSON(t, filepath.Join(dir, "package-lock.json"), map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                    map[string]any{"dependencies": map[string]string{"lodash": "^4.17.0"}},
			"node_modules/lodash": map[string]any{"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": testIntegrity()},
		},
	})

	manager := NPM{
		JSON:       true,
		ProjectDir: dir,
		Sandbox:    sandbox.Config{Workspace: t.TempDir()},
		DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
			packageDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(`{"name":"lodash","version":"4.17.21"}`), 0o600); err != nil {
				return "", err
			}
			return packageDir, nil
		},
		SandboxRunner: func(config sandbox.Config, command ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
			if config.ProjectDir != dir {
				t.Fatalf("sandbox project directory = %q, want %q", config.ProjectDir, dir)
			}
			return analyzer.FileChanges{}, nil, nil, nil
		},
	}

	oldStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	installErr := manager.Install(nil)
	_ = write.Close()
	os.Stdout = oldStdout
	if installErr != nil {
		t.Fatalf("project Install returned error: %v", installErr)
	}
	var response map[string]any
	if err := json.NewDecoder(read).Decode(&response); err != nil {
		t.Fatalf("decode project JSON: %v", err)
	}
	if response["scope"] != "project" || response["packages_analyzed"] != float64(1) {
		t.Fatalf("unexpected project report: %v", response)
	}
}

func testIntegrity() string {
	digest := sha512.Sum512(nil)
	return "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
}

func writeProjectJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
