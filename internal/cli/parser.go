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
		case "audit":
			return Command{PackageManager: "audit", Operation: "audit"}, nil
		case "setup":
			return Command{PackageManager: "setup", Operation: "setup"}, nil
		}
	}

	if len(args) < 2 {
		return Command{}, fmt.Errorf("usage: saferun <package-manager> <operation> [package] [options]\n\nExample: saferun npm install express --save")
	}

	if len(args) == 2 {
		if args[0] == "npm" && args[1] == "install" {
			return Command{}, fmt.Errorf("usage: saferun npm install <package> [options]\n\nExample: saferun npm install express --save")
		}
	}

	return Command{
		PackageManager: args[0],
		Operation:      args[1],
		Arguments:      args[2:],
	}, nil
}
