package packagex

import (
	"testing"
)

func TestResolveLodash(t *testing.T) {
	pkg, err := Resolve("lodash")
	if err != nil {
		t.Fatal(err)
	}

	if pkg.Name != "lodash" {
		t.Fatalf("expected lodash, got %s", pkg.Name)
	}

	if pkg.Version == "" {
		t.Fatal("expected version")
	}

	if pkg.TarballURL == "" {
		t.Fatal("expected tarball URL")
	}

	if pkg.Integrity == "" {
		t.Fatal("expected integrity")
	}
}
