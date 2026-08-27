package package_manager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/prompt"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/risk"
	"github.com/dag12y/saferun/internal/sandbox"
)

type NPM struct {
	Sandbox  sandbox.Config
	Registry registry.NPMRegistry
}

func (n NPM) Name() string {
	return "npm"
}

func (n NPM) Install(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no npm package specified")
	}

	packageName := args[0]

	// Resolve package metadata.
	fmt.Printf("Resolving package: %s\n", packageName)

	pkg, err := n.Registry.Resolve(packageName)
	if err != nil {
		return err
	}

	fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.Version)
	fmt.Printf("Integrity: %s\n", pkg.Integrity)
	fmt.Printf("Tarball: %s\n", pkg.TarballURL)

	// Download and extract package.
	fmt.Println()
	fmt.Println("Downloading package...")

	packagePath, err := n.Registry.Download(pkg)
	if err != nil {
		return err
	}

	defer os.RemoveAll(packagePath)

	fmt.Printf("Extracted to: %s\n", packagePath)

	// Static analysis.
	fmt.Println()
	fmt.Println("SafeRun Security Report")
	fmt.Println("-----------------------")

	analysis, err := analyzer.AnalyzePackageJSON(
		filepath.Join(packagePath, "package.json"),
	)
	if err != nil {
		return err
	}

	// Convert analyzer findings into risk findings.
	findings := []risk.Finding{}

	if analysis.HasInstallScripts {
		for name, command := range analysis.Scripts {
			findings = append(findings, risk.Finding{
				Name:        name,
				Description: command,
				Severity:    risk.Medium,
			})
		}
	}

	report := risk.Analyze(findings)

	if len(report.Findings) == 0 {
		fmt.Println("✓ No suspicious lifecycle scripts detected")
	} else {
		for _, finding := range report.Findings {
			fmt.Printf(
				"⚠ %s [%s]: %s\n",
				finding.Name,
				finding.Severity,
				finding.Description,
			)
		}
	}

	fmt.Printf("\nRisk: %s\n", report.Level)

	// Ask user before installation.
	fmt.Println()

	if !prompt.Confirm(fmt.Sprintf(
		"Install %s@%s?",
		pkg.Name,
		pkg.Version,
	)) {
		fmt.Println("Installation cancelled.")
		return nil
	}

	// Install inside sandbox.
	fmt.Println()
	fmt.Println("Installing package...")

	command := append([]string{"npm", "install"}, args...)

	return sandbox.Run(n.Sandbox, command...)
}
