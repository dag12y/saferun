package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileFinding struct {
	Path        string
	Description string
	Severity    string
}

func AnalyzeFiles(root string) ([]FileFinding, error) {
	var findings []FileFinding

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("get relative path: %w", err)
		}

		// Ignore package.json because it is already analyzed separately.
		if relativePath == "package.json" {
			return nil
		}

		// Suspicious executable files.
		if info.Mode().Perm()&0111 != 0 {
			findings = append(findings, FileFinding{
				Path:        relativePath,
				Description: "Executable file",
				Severity:    "MEDIUM",
			})
		}

		// Suspicious hidden files/directories.
		for _, part := range strings.Split(filepath.ToSlash(relativePath), "/") {
			if strings.HasPrefix(part, ".") &&
				part != "." &&
				part != ".." {
				findings = append(findings, FileFinding{
					Path:        relativePath,
					Description: "Hidden file",
					Severity:    "LOW",
				})
				break
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("analyze package files: %w", err)
	}

	return findings, nil
}
