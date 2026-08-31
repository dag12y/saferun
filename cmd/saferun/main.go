package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dag12y/saferun/internal/audit"
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
		PidsLimit: 128,
		Timeout:   5 * time.Minute,
	}

	switch command.PackageManager {
	case "audit":
		events, err := audit.ReadRecent(20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: read audit log: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("SafeRun Audit Log")
		fmt.Println("-----------------")
		fmt.Println(audit.FormatRecent(events))
		return
	case "npm":
		if command.Operation != "install" {
			fmt.Fprintf(os.Stderr, "Error: unsupported npm operation: %s\n\nUsage:\n  saferun npm install <package> [options]\n", command.Operation)
			os.Exit(1)
		}

		manager := package_manager.NPM{
			Sandbox: config,
			Registry: registry.NPMRegistry{
				BaseURL: "https://registry.npmjs.org",
			},
		}

		if err := manager.Install(command.Arguments); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(
			os.Stderr,
			"Error: unsupported package manager: %s\n\nUsage:\n  saferun npm install <package> [options]\n",
			command.PackageManager,
		)
		os.Exit(1)
	}
}
