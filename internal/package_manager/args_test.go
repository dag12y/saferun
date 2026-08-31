package package_manager

import (
	"reflect"
	"testing"
)

func TestParseInstallArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want InstallArgs
	}{
		{name: "single package", in: []string{"lodash"}, want: InstallArgs{Packages: []string{"lodash"}}},
		{name: "multiple packages", in: []string{"express", "lodash"}, want: InstallArgs{Packages: []string{"express", "lodash"}}},
		{name: "with version", in: []string{"express@5.2.1"}, want: InstallArgs{Packages: []string{"express@5.2.1"}}},
		{name: "local package", in: []string{"./local-package"}, want: InstallArgs{Packages: []string{"./local-package"}}},
		{name: "flag after packages", in: []string{"express", "--save"}, want: InstallArgs{Packages: []string{"express"}, Flags: []string{"--save"}}},
		{name: "flag before package", in: []string{"-D", "typescript"}, want: InstallArgs{Packages: []string{"typescript"}, Flags: []string{"-D"}}},
		{name: "save-dev flag", in: []string{"express", "--save-dev"}, want: InstallArgs{Packages: []string{"express"}, Flags: []string{"--save-dev"}}},
		{name: "flag with value", in: []string{"--tag", "next", "express"}, want: InstallArgs{Packages: []string{"express"}, Flags: []string{"--tag", "next"}}},
		{name: "multiple packages with flags", in: []string{"express", "lodash", "--save", "--save-exact"}, want: InstallArgs{Packages: []string{"express", "lodash"}, Flags: []string{"--save", "--save-exact"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseInstallArgs(tc.in)
			if err != nil {
				t.Fatalf("ParseInstallArgs returned unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseInstallArgs(%v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseInstallArgsMissingPackage(t *testing.T) {
	if _, err := ParseInstallArgs([]string{"--save"}); err == nil {
		t.Fatal("expected missing package to return an error")
	}
}
