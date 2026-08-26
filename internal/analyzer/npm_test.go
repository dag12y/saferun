package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzePackageJSONDetectsInstallScripts(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "package.json")

	content := `{
		"name": "test-package",
		"scripts": {
			"postinstall": "node install.js"
		}
	}`

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzePackageJSON(path)
	if err != nil {
		t.Fatal(err)
	}

	if !result.HasInstallScripts {
		t.Fatal("expected install script to be detected")
	}

	if result.Scripts["postinstall"] != "node install.js" {
		t.Fatalf("unexpected script: %s", result.Scripts["postinstall"])
	}
}

func TestAnalyzePackageJSONWithoutInstallScripts(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "package.json")

	content := `{
		"name": "test-package",
		"scripts": {
			"test": "vitest"
		}
	}`

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := AnalyzePackageJSON(path)
	if err != nil {
		t.Fatal(err)
	}

	if result.HasInstallScripts {
		t.Fatal("did not expect install script")
	}
}
