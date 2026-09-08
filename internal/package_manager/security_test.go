package package_manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dag12y/saferun/internal/registry"
)

func TestValidateDownloadedPackageIdentity(t *testing.T) {
	cases := []struct {
		name     string
		manifest string
		wantErr  bool
	}{
		{"matching", `{"name":"pkg","version":"1.2.3"}`, false},
		{"wrong name", `{"name":"other","version":"1.2.3"}`, true},
		{"wrong version", `{"name":"pkg","version":"1.2.4"}`, true},
		{"missing name", `{"version":"1.2.3"}`, true},
		{"missing version", `{"name":"pkg"}`, true},
		{"scoped matching", `{"name":"@scope/pkg","version":"1.2.3"}`, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(test.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			err := validateDownloadedPackageIdentity(registry.PackageInfo{Name: "pkg", Version: "1.2.3"}, dir)
			if test.name == "scoped matching" {
				err = validateDownloadedPackageIdentity(registry.PackageInfo{Name: "@scope/pkg", Version: "1.2.3"}, dir)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestValidateHostInstallArgsRejectsRedirects(t *testing.T) {
	for _, arg := range []string{"--prefix=/tmp/other", "--userconfig=/tmp/npmrc", "--globalconfig", "--registry=https://evil.invalid", "-g", "--global", "-c", "-cfoo=bar"} {
		if err := validateHostInstallArgs([]string{"install", arg}); err == nil {
			t.Fatalf("expected %q to be rejected", arg)
		}
	}
}

func TestPrepareNPMEnvironmentFiltersSecrets(t *testing.T) {
	t.Setenv("PATH", "/safe/path")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-for-child")
	t.Setenv("NPM_TOKEN", "not-for-child")
	env, cleanup, err := prepareNPMEnvironment(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "AWS_SECRET_ACCESS_KEY") || strings.Contains(joined, "NPM_TOKEN") {
		t.Fatalf("secret environment variable was inherited: %s", joined)
	}
	if !strings.Contains(joined, "PATH=/safe/path") {
		t.Fatalf("PATH was not preserved: %s", joined)
	}
}

func TestPrepareNPMEnvironmentRejectsProjectNpmrc(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("//registry.npmjs.org/:_authToken=fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := prepareNPMEnvironment(dir)
	cleanup()
	if err == nil || !strings.Contains(err.Error(), ".npmrc") {
		t.Fatalf("expected project .npmrc rejection, got %v", err)
	}
}

func TestValidateProjectLockfileRejectsMismatchedPackageEntry(t *testing.T) {
	dir := t.TempDir()
	manifest := projectManifest{Dependencies: map[string]string{"pkg": "1.2.3"}}
	lock := map[string]any{
		"lockfileVersion": 3,
		"packages": map[string]any{
			"":                 map[string]any{"dependencies": map[string]string{"pkg": "1.2.3"}},
			"node_modules/pkg": map[string]any{"name": "other", "version": "1.2.3", "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.2.3.tgz", "integrity": testIntegrity()},
		},
	}
	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateProjectLockfile(path, manifest); err == nil {
		t.Fatal("expected package path/name mismatch to fail")
	}
}
