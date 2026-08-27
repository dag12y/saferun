package package_manager

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/prompt"
	"github.com/dag12y/saferun/internal/registry"
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

	fmt.Println()
	fmt.Println("Static Analysis")

	analysis, err := analyzer.AnalyzePackageJSON(
		filepath.Join(packagePath, "package.json"),
	)
	if err != nil {
		return err
	}

	if analysis.HasInstallScripts {
		fmt.Println("⚠ Lifecycle scripts detected:")

		for name, command := range analysis.Scripts {
			fmt.Printf("  %s: %s\n", name, command)
		}
	} else {
		fmt.Println("✓ No lifecycle scripts detected")
	}
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
