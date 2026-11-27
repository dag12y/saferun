package cli

import (
	"fmt"
	"strings"
)

type Command struct {
	PackageManager string
	Operation      string
	Arguments      []string
	JSON           bool
	Format         string
}

func Parse(args []string) (Command, error) {
	jsonOutput := false
	format := ""
	filteredArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" {
			jsonOutput = true
			format = "json"
			continue
		}
		if strings.HasPrefix(arg, "--format=") {
			val := strings.ToLower(strings.TrimPrefix(arg, "--format="))
			format = val
			if val == "json" {
				jsonOutput = true
			}
			continue
		}
		if arg == "--format" && i+1 < len(args) {
			val := strings.ToLower(args[i+1])
			format = val
			if val == "json" {
				jsonOutput = true
			}
			i++
			continue
		}
		filteredArgs = append(filteredArgs, arg)
	}
	args = filteredArgs

	if format != "" && format != "json" && format != "sarif" {
		return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("unsupported output format %q (supported: json, sarif)", format)
	}

	if len(args) == 0 {
		return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("usage: saferun <package-manager> <operation> [package] [options]\n\nExample: saferun npm install express --save")
	}

	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h", "help":
			return Command{PackageManager: "help", JSON: jsonOutput, Format: format}, nil
		case "--version", "version":
			return Command{PackageManager: "version", JSON: jsonOutput, Format: format}, nil
		case "audit":
			return Command{PackageManager: "audit", Operation: "audit", JSON: jsonOutput, Format: format}, nil
		case "setup":
			return Command{PackageManager: "setup", Operation: "setup", JSON: jsonOutput, Format: format}, nil
		case "npm":
			return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("usage: saferun npm install <package> [options]\n\nExample: saferun npm install express --save")
		default:
			return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("unknown command %q\n\nRun \"saferun --help\" for usage", args[0])
		}
	}

	if len(args) == 2 {
		if args[0] == "audit" && (args[1] == "--all" || args[1] == "--clear") {
			return Command{PackageManager: "audit", Operation: "audit", Arguments: []string{args[1]}, JSON: jsonOutput, Format: format}, nil
		}
		if args[0] == "npm" && isNPMInstallAlias(args[1]) {
			return Command{PackageManager: "npm", Operation: "install", JSON: jsonOutput, Format: format}, nil
		}
	}

	if len(args) == 3 && args[0] == "audit" &&
		((args[1] == "--all" && args[2] == "--clear") || (args[1] == "--clear" && args[2] == "--all")) {
		return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("audit options --all and --clear cannot be combined")
	}

	if len(args) < 2 {
		return Command{JSON: jsonOutput, Format: format}, fmt.Errorf("usage: saferun <package-manager> <operation> [package] [options]\n\nExample: saferun npm install express --save")
	}

	operation := args[1]
	if args[0] == "npm" && isNPMInstallAlias(operation) {
		operation = "install"
	}

	return Command{
		PackageManager: args[0],
		Operation:      operation,
		Arguments:      args[2:],
		JSON:           jsonOutput,
		Format:         format,
	}, nil
}

func isNPMInstallAlias(op string) bool {
	return op == "install" || op == "i" || op == "add"
}
