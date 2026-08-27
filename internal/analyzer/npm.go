package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
)

type NPMAnalysis struct {
	HasInstallScripts bool
	Scripts           map[string]string
	Dependencies      int
	DevDependencies   int
}

func AnalyzePackageJSON(path string) (NPMAnalysis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return NPMAnalysis{}, fmt.Errorf("read package.json: %w", err)
	}

	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return NPMAnalysis{}, fmt.Errorf("parse package.json: %w", err)
	}

	installScripts := make(map[string]string)

	for name, command := range pkg.Scripts {
		switch name {
		case "preinstall", "install", "postinstall", "prepare":
			installScripts[name] = command
		}
	}

	return NPMAnalysis{
		HasInstallScripts: len(installScripts) > 0,
		Scripts:           installScripts,
		Dependencies:      len(pkg.Dependencies),
		DevDependencies:   len(pkg.DevDependencies),
	}, nil
}
