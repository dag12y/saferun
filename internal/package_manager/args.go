package package_manager

import (
	"fmt"
	"strings"
)

// InstallArgs separates package specifiers from npm flags and any values that
// belong to those flags, while preserving the original install arguments for the
// final real npm install and the sandboxed install.
type InstallArgs struct {
	Packages []string
	Flags    []string
}

var flagValues = map[string]bool{
	"--tag":             true,
	"--workspace":       true,
	"--prefix":          true,
	"--cache":           true,
	"--userconfig":      true,
	"--globalconfig":    true,
	"--loglevel":        true,
	"--registry":        true,
	"--save-prefix":     true,
	"--color":           true,
	"--fund":            true,
	"--include-workspace-root": true,
	"--workspaces":      true,
	"-w":                true,
	"-C":                true,
	"--workspace-root":  true,
	"--otp":             true,
	"--strict-peer-deps": true,
}

var booleanFlags = map[string]bool{
	"-D": true, "-P": true, "-O": true, "-E": true, "-g": true,
	"--global": true, "--save": true, "--save-dev": true, "--save-prod": true,
	"--no-save": true, "--no-package-lock": true, "--package-lock-only": true,
	"--production": true, "--dry-run": true, "--prefer-offline": true,
	"--ignore-scripts": true, "--legacy-peer-deps": true, "--audit": true,
	"--fund": true, "--no-fund": true, "--silent": true, "--verbose": true,
	"--quiet": true, "--optional": true, "--no-optional": true,
	"--force": true, "--no-audit": true,
}

func ParseInstallArgs(args []string) (InstallArgs, error) {
	parsed := InstallArgs{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if _, isBoolean := booleanFlags[arg]; isBoolean {
				parsed.Flags = append(parsed.Flags, arg)
				continue
			}
			if _, takesValue := flagValues[arg]; takesValue {
				parsed.Flags = append(parsed.Flags, arg)
				if i+1 < len(args) && args[i+1] != "--" {
					parsed.Flags = append(parsed.Flags, args[i+1])
					i++
				}
				continue
			}
			if i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.HasPrefix(args[i-1], "--") {
				parsed.Flags = append(parsed.Flags, arg)
				continue
			}
			parsed.Flags = append(parsed.Flags, arg)
			continue
		}
		parsed.Packages = append(parsed.Packages, arg)
	}

	if len(parsed.Packages) == 0 {
		return InstallArgs{}, fmt.Errorf("usage: saferun npm install <package> [options]")
	}

	return parsed, nil
}
