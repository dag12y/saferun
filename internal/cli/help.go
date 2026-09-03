package cli

import "fmt"

func HelpText(version string) string {
	return fmt.Sprintf(`SafeRun %s

Secure package installation with sandboxed security analysis.

Usage:
  saferun <command> [arguments]

Commands:
  setup       Check and prepare the SafeRun environment
  npm         Securely install npm packages
  audit       View the SafeRun audit log
  version     Show SafeRun version
  help        Show help information

Options:
  -h, --help  Show help
      --version  Show version information
`, version)
}