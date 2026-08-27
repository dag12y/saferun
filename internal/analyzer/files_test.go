package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeFilesDetectsExecutable(t *testing.T) {
	root := t.TempDir()

	file := filepath.Join(root, "install.sh")

	err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := AnalyzeFiles(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected executable file to be detected")
	}
}

func TestAnalyzeFilesDetectsHiddenFile(t *testing.T) {
	root := t.TempDir()

	file := filepath.Join(root, ".hidden")

	err := os.WriteFile(file, []byte("test"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := AnalyzeFiles(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected hidden file to be detected")
	}
}

func TestAnalyzeFilesIgnoresPackageJSON(t *testing.T) {
	root := t.TempDir()

	file := filepath.Join(root, "package.json")

	err := os.WriteFile(file, []byte("{}"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := AnalyzeFiles(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
