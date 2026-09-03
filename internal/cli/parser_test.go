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

func TestHelpText(t *testing.T) {
	help := HelpText("v1.0.3-test")
	for _, expected := range []string{"SafeRun v1.0.3-test", "Usage:", "--help", "setup", "npm", "audit", "version"} {
		if !strings.Contains(help, expected) {
			t.Errorf("help output does not contain %q", expected)
		}
	}
}
