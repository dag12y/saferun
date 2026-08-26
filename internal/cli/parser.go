package cli

import "fmt"

type Command struct {
	PackageManager string
	Operation      string
	Arguments      []string
}

func Parse(args []string) (Command, error) {
	if len(args) < 3 {
		return Command{}, fmt.Errorf(
			"usage: saferun <package-manager> <operation> <package>",
		)
	}

	return Command{
		PackageManager: args[0],
		Operation:      args[1],
		Arguments:      args[2:],
	}, nil
}
