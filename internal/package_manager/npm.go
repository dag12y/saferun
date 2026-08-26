package package_manager

import (
	"fmt"

	"github.com/dag12y/saferun/internal/sandbox"
)

type NPM struct {
	Sandbox sandbox.Config
}

func (n NPM) Name() string {
	return "npm"
}

func (n NPM) Install(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no npm package specified")
	}

	command := append([]string{"npm", "install"}, args...)

	return sandbox.Run(n.Sandbox, command...)
}
