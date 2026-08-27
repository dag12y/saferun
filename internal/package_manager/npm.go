package package_manager

import (
	"fmt"

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

	command := append([]string{"npm", "install"}, args...)

	return sandbox.Run(n.Sandbox, command...)
}
