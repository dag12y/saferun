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

	fmt.Printf("Resolving package: %s\n", packageName)

	pkg, err := n.Registry.Resolve(packageName)
	if err != nil {
		return err
	}

	fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.Version)
	fmt.Printf("Integrity: %s\n", pkg.Integrity)
	fmt.Printf("Tarball: %s\n", pkg.TarballURL)

	fmt.Println()
	fmt.Println("Downloading package...")

	packagePath, err := n.Registry.Download(pkg)
	if err != nil {
		return err
	}

	defer os.RemoveAll(packagePath)

	fmt.Printf("Extracted to: %s\n", packagePath)

	// Static analysis.
	analysis, err := analyzer.AnalyzePackageJSON(
		filepath.Join(packagePath, "package.json"),
	)
	if err != nil {
		return err
	}

	// Build risk findings.
	var findings []risk.Finding

	for name, command := range analysis.Scripts {
		scriptFindings := analyzer.AnalyzeScript(command)

		if len(scriptFindings) == 0 {
			findings = append(findings, risk.Finding{
				Name:        name,
				Description: command,
				Severity:    risk.Medium,
			})

			continue
		}

		for _, scriptFinding := range scriptFindings {
			severity := risk.Level(scriptFinding.Severity)

			findings = append(findings, risk.Finding{
				Name: fmt.Sprintf(
					"%s: %s",
					name,
					scriptFinding.Pattern,
				),
				Description: scriptFinding.Description,
				Severity:    severity,
			})
		}
	}

	fileFindings, err := analyzer.AnalyzeFiles(packagePath)
	if err != nil {
		return err
	}

	for _, finding := range fileFindings {
		findings = append(findings, risk.Finding{
			Name:        finding.Path,
			Description: finding.Description,
			Severity:    risk.Level(finding.Severity),
		})
	}

	report := risk.Analyze(findings)

	// Security report.
	fmt.Println()
	fmt.Println("SafeRun Security Report")
	fmt.Println("-----------------------")

	fmt.Printf("Package: %s@%s\n\n", pkg.Name, pkg.Version)

	fmt.Println("Metadata")
	fmt.Printf("  Dependencies: %d\n", analysis.Dependencies)
	fmt.Printf("  Dev dependencies: %d\n", analysis.DevDependencies)

	fmt.Println()
	fmt.Println("Lifecycle Scripts")

	if len(analysis.Scripts) == 0 {
		fmt.Println("  ✓ None detected")
	} else {
		for name, command := range analysis.Scripts {
			fmt.Printf("  ⚠ %s: %s\n", name, command)

			scriptFindings := analyzer.AnalyzeScript(command)

			for _, finding := range scriptFindings {
				fmt.Printf(
					"      └─ %s [%s]\n",
					finding.Description,
					finding.Severity,
				)
			}
		}
	}

	fmt.Println()
	fmt.Println("File Analysis")

	if len(fileFindings) == 0 {
		fmt.Println("  ✓ No suspicious files detected")
	} else {
		for _, finding := range fileFindings {
			fmt.Printf(
				"  ⚠ %s [%s]: %s\n",
				finding.Path,
				finding.Severity,
				finding.Description,
			)
		}
	}

	fmt.Printf("\nRisk: %s\n", report.Level)

	// User approval.
	fmt.Println()

	if !prompt.Confirm(fmt.Sprintf(
		"Install %s@%s?",
		pkg.Name,
		pkg.Version,
	)) {
		fmt.Println("Installation cancelled.")
		return nil
	}

	fmt.Println()
	fmt.Println("Installing package...")

	command := append([]string{"npm", "install"}, args...)

	return sandbox.Run(n.Sandbox, command...)
}
