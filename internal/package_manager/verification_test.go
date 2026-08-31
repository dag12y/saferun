package package_manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestInstallationVerifierSinglePackage(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "4.18.1"},
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "lodash", "package.json"), map[string]any{
		"name":    "lodash",
		"version": "4.18.1",
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"lodash"}, nil)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected verification success, got errors: %v", result.Errors)
	}
	if len(result.Packages) != 1 {
		t.Fatalf("expected 1 package result, got %d", len(result.Packages))
	}
	if result.Packages[0].InstalledVersion != "4.18.1" {
		t.Fatalf("expected version 4.18.1, got %q", result.Packages[0].InstalledVersion)
	}
}

func TestInstallationVerifierMissingPackage(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name": "demo",
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"lodash"}, nil)
	if err == nil {
		t.Fatal("expected verification error for missing package")
	}
	if result.Success {
		t.Fatal("expected verification to fail")
	}
}

func TestInstallationVerifierWrongVersion(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"version":      "1.0.0",
		"dependencies": map[string]string{"lodash": "4.18.1"},
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "lodash", "package.json"), map[string]any{
		"name":    "lodash",
		"version": "4.17.21",
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"lodash@4.18.1"}, nil)
	if err == nil {
		t.Fatal("expected version mismatch to fail verification")
	}
	if result.Success {
		t.Fatal("expected failed verification for wrong version")
	}
}

func TestInstallationVerifierMultiplePackagesAndScopedPackages(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name": "demo",
		"dependencies": map[string]string{
			"lodash":      "4.18.1",
			"dotenv":      "17.4.2",
			"@types/node": "24.0.0",
		},
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "lodash", "package.json"), map[string]any{
		"name":    "lodash",
		"version": "4.18.1",
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "dotenv", "package.json"), map[string]any{
		"name":    "dotenv",
		"version": "17.4.2",
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "@types", "node", "package.json"), map[string]any{
		"name":    "@types/node",
		"version": "24.0.0",
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"lodash", "dotenv", "@types/node"}, nil)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected verification success, got errors: %v", result.Errors)
	}
	if len(result.Packages) != 3 {
		t.Fatalf("expected 3 package results, got %d", len(result.Packages))
	}
}

func TestInstallationVerifierDevDependencyRecorded(t *testing.T) {
	projectDir := t.TempDir()
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":            "demo",
		"devDependencies": map[string]string{"typescript": "5.6.3"},
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "typescript", "package.json"), map[string]any{
		"name":    "typescript",
		"version": "5.6.3",
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"typescript"}, []string{"-D"})
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected verification success, got errors: %v", result.Errors)
	}
	if result.Packages[0].RecordedIn != "devDependencies" {
		t.Fatalf("expected dev dependency recording, got %q", result.Packages[0].RecordedIn)
	}
}

func TestInstallationVerifierLocalPackage(t *testing.T) {
	projectDir := t.TempDir()
	localDir := filepath.Join(projectDir, "local-pkg")
	writeJSON(t, filepath.Join(localDir, "package.json"), map[string]any{
		"name":    "local-pkg",
		"version": "0.1.0",
	})
	writeJSON(t, filepath.Join(projectDir, "node_modules", "local-pkg", "package.json"), map[string]any{
		"name":    "local-pkg",
		"version": "0.1.0",
	})
	writeJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
		"name":         "demo",
		"dependencies": map[string]string{"local-pkg": "0.1.0"},
	})

	verifier := InstallationVerifier{ProjectDir: projectDir}
	result, err := verifier.Verify([]string{"./local-pkg"}, nil)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected local package verification success, got errors: %v", result.Errors)
	}
	if result.Packages[0].Name != "local-pkg" {
		t.Fatalf("expected local package name local-pkg, got %q", result.Packages[0].Name)
	}
}
