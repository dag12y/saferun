package cli

import (
	"strings"
	"testing"
)

func TestParseMetadataCommands(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "long help", arg: "--help", want: "help"},
		{name: "short help", arg: "-h", want: "help"},
		{name: "help command", arg: "help", want: "help"},
		{name: "long version", arg: "--version", want: "version"},
		{name: "version command", arg: "version", want: "version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := Parse([]string{test.arg})
			if err != nil {
				t.Fatalf("Parse(%q) returned error: %v", test.arg, err)
			}
			if command.PackageManager != test.want {
				t.Fatalf("Parse(%q) package manager = %q, want %q", test.arg, command.PackageManager, test.want)
			}
		})
	}
}

func TestParseUnknownCommand(t *testing.T) {
	_, err := Parse([]string{"something"})
	if err == nil {
		t.Fatal("Parse returned nil error for unknown command")
	}
	if err.Error() != "unknown command \"something\"\n\nRun \"saferun --help\" for usage" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseJSONFlag(t *testing.T) {
	command, err := Parse([]string{"npm", "install", "lodash", "--json"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !command.JSON {
		t.Fatal("expected JSON output to be enabled")
	}
	if strings.Join(command.Arguments, " ") != "lodash" {
		t.Fatalf("expected --json to be removed from npm arguments, got %v", command.Arguments)
	}
}

func TestParseProjectInstall(t *testing.T) {
	command, err := Parse([]string{"npm", "install", "--json"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if command.PackageManager != "npm" || command.Operation != "install" || !command.JSON {
		t.Fatalf("unexpected project command: %#v", command)
	}
	if len(command.Arguments) != 0 {
		t.Fatalf("expected no package arguments, got %v", command.Arguments)
	}
}

func TestParseNPMInstallAliases(t *testing.T) {
	for _, alias := range []string{"install", "i", "add"} {
		cmd, err := Parse([]string{"npm", alias, "lodash"})
		if err != nil {
			t.Fatalf("Parse(npm %s lodash) returned error: %v", alias, err)
		}
		if cmd.Operation != "install" {
			t.Fatalf("expected operation 'install' for alias %q, got %q", alias, cmd.Operation)
		}

		projCmd, err := Parse([]string{"npm", alias})
		if err != nil {
			t.Fatalf("Parse(npm %s) returned error: %v", alias, err)
		}
		if projCmd.Operation != "install" {
			t.Fatalf("expected project operation 'install' for alias %q, got %q", alias, projCmd.Operation)
		}
	}
}

func TestHelpText(t *testing.T) {
	help := HelpText("v1.0.3-test")
	for _, expected := range []string{"SafeRun v1.0.3-test", "Usage:", "--help", "setup", "npm", "audit", "version"} {
		if !strings.Contains(help, expected) {
			t.Errorf("help output does not contain %q", expected)
		}
	}
}
