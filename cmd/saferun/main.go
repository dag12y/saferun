package main

import (
	"fmt"
	"os"

	"github.com/dag12y/saferun/internal/cli"
	"github.com/dag12y/saferun/internal/package_manager"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/sandbox"
)

func main() {
	fmt.Println("SafeRun")
	fmt.Println("Secure package installation sandbox")
	fmt.Println()

	command, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	config := sandbox.Config{
		Image:     "saferun-node:dev",
		Network:   "bridge",
		Memory:    "512m",
		CPUs:      "1",
		Workspace: "/tmp/saferun-workspace",
	}

	switch command.PackageManager {
	case "npm":
		if command.Operation != "install" {
			fmt.Fprintln(os.Stderr, "Error: only npm install is currently supported")
			os.Exit(1)
		}

		manager := package_manager.NPM{
			Sandbox: config,
			Registry: registry.NPMRegistry{
				BaseURL: "https://registry.npmjs.org",
			},
		}

		if err := manager.Install(command.Arguments); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(
			os.Stderr,
			"Error: unsupported package manager: %s\n",
			command.PackageManager,
		)
		os.Exit(1)
	}
}
