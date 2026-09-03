package main

import (
	"fmt"
	"os"

	"github.com/dag12y/saferun/internal/audit"
	"github.com/dag12y/saferun/internal/cli"
	"github.com/dag12y/saferun/internal/package_manager"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/sandbox"
	"github.com/dag12y/saferun/internal/setup"
	"github.com/dag12y/saferun/internal/version"
)

func main() {
	command, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	switch command.PackageManager {
	case "help":
		fmt.Print(cli.HelpText(version.Version))
		return
	case "version":
		fmt.Printf("SafeRun %s\n", version.Version)
		return
	}

	fmt.Println("SafeRun")
	fmt.Println("Secure package installation sandbox")
	fmt.Println()

	config := sandbox.DefaultConfig()
	dockerCtx, dockerCancel := setup.DockerTimeoutContext()
	defer dockerCancel()
	pullCtx, pullCancel := setup.PullTimeoutContext()
	defer pullCancel()

	switch command.PackageManager {
	case "audit":
		showAll := false
		if len(command.Arguments) == 1 && command.Arguments[0] == "--all" {
			showAll = true
		}
		events, malformed, err := audit.ReadRecentWithStats(audit.DefaultPath(), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: read audit log: %v\n", err)
			os.Exit(1)
		}
		if !showAll && len(events) > 20 {
			events = events[:20]
		}
		if malformed > 0 {
			fmt.Printf("Warning: skipped %d malformed audit entry(s).\n\n", malformed)
		}
		fmt.Println("SafeRun Audit Log")
		fmt.Println("-----------------")
		fmt.Println(audit.FormatRecent(events))
		if showAll {
			fmt.Printf("\nShowing %d total event(s).\n", len(events))
		} else if len(events) == 0 {
			fmt.Println("\nShowing 0 most recent events. Use 'saferun audit --all' to view all events.")
		} else if len(events) < 20 {
			fmt.Printf("\nShowing %d most recent event(s). Use 'saferun audit --all' to view all events.\n", len(events))
		} else {
			fmt.Println("\nShowing 20 most recent events. Use 'saferun audit --all' to view all events.")
		}
		return
	case "setup":
		fmt.Println("SafeRun")
		fmt.Println("Secure package installation sandbox")
		fmt.Println()
		fmt.Println("SafeRun Setup")
		fmt.Println("-------------")
		fmt.Println()
		fmt.Println("Docker")
		dockerStatus, err := setup.CheckDockerAvailability(dockerCtx, setup.RealDocker{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: determine Docker status: %v\n", err)
			os.Exit(1)
		}
		if !dockerStatus.Installed {
			fmt.Println("✗ Docker is not installed")
			fmt.Println()
			fmt.Println("SafeRun requires Docker to create isolated package sandboxes.")
			fmt.Println("Please install Docker and run `saferun setup` again.")
			os.Exit(1)
		}
		fmt.Println("✓ Docker is installed")
		if !dockerStatus.DaemonRunning {
			fmt.Println("✗ Docker daemon is not running")
			fmt.Println()
			fmt.Println("Please start Docker and run `saferun setup` again.")
			os.Exit(1)
		}
		fmt.Println("✓ Docker daemon is running")
		fmt.Println()
		fmt.Println("Sandbox Image")
		imageAvailable, err := setup.CheckSandboxImage(dockerCtx, setup.RealDocker{}, config.Image)
		if err != nil {
			fmt.Printf("✗ SafeRun sandbox image not found\n\nPulling %s...\n", config.Image)
			if _, err := setup.EnsureSandboxImage(pullCtx, setup.RealDocker{}, config.Image); err != nil {
				fmt.Println("✗ Failed to download SafeRun sandbox image")
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("✓ Sandbox image downloaded")
		} else if imageAvailable {
			fmt.Println("✓ SafeRun sandbox image is available")
		}
		fmt.Println()
		fmt.Println("✓ SafeRun setup complete.")
		fmt.Println()
		fmt.Println("You can now run:")
		fmt.Println()
		fmt.Printf("  saferun npm install <package>\n")
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
