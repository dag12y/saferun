package cli

import "fmt"

type Command struct {
	PackageManager string
	Operation      string
	Arguments      []string
}

func Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("usage: saferun <package-manager> <operation> [package] [options]\n\nExample: saferun npm install express --save")
	}

	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h", "help":
			return Command{PackageManager: "help"}, nil
		case "--version", "version":
			return Command{PackageManager: "version"}, nil
		case "audit":
			return Command{PackageManager: "audit", Operation: "audit"}, nil
		case "setup":
			return Command{PackageManager: "setup", Operation: "setup"}, nil
		case "npm":
			return Command{}, fmt.Errorf("usage: saferun npm install <package> [options]\n\nExample: saferun npm install express --save")
		default:
			return Command{}, fmt.Errorf("unknown command %q\n\nRun \"saferun --help\" for usage", args[0])
		}
	}

	if len(args) == 2 {
		if args[0] == "audit" && (args[1] == "--all" || args[1] == "--clear") {
			return Command{PackageManager: "audit", Operation: "audit", Arguments: []string{args[1]}}, nil
		}
		if args[0] == "npm" && args[1] == "install" {
			return Command{}, fmt.Errorf("usage: saferun npm install <package> [options]\n\nExample: saferun npm install express --save")
		}
	}

	if len(args) == 3 && args[0] == "audit" &&
		((args[1] == "--all" && args[2] == "--clear") || (args[1] == "--clear" && args[2] == "--all")) {
		return Command{}, fmt.Errorf("audit options --all and --clear cannot be combined")
	}

	if len(args) < 2 {
		return Command{}, fmt.Errorf("usage: saferun <package-manager> <operation> [package] [options]\n\nExample: saferun npm install express --save")
	}

	return Command{
		PackageManager: args[0],
		Operation:      args[1],
		Arguments:      args[2:],
	}, nil
}
