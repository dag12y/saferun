package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMissingConfigReturnsDefaults(t *testing.T) {
	t.Setenv("SAFERUN_CONFIG", "")
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if !cfg.OSVEnabled() {
		t.Fatal("expected OSV to be enabled by default")
	}
	if cfg.Policy.BlockOnMedium {
		t.Fatal("expected BlockOnMedium to be false by default")
	}
}

func TestLoadProjectSaferunrc(t *testing.T) {
	t.Setenv("SAFERUN_CONFIG", "")
	dir := t.TempDir()
	content := `{
		"sandbox": {
			"memory": "1g",
			"cpus": "2",
			"pids_limit": 256,
			"timeout": "10m",
			"image": "custom/node:1.0"
		},
		"network": {
			"allowed_hosts": ["npm.internal.corp", "*.artifactory.local"]
		},
		"policy": {
			"block_on_medium": true
		},
		"osv": {
			"enabled": false
		}
	}`
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Sandbox.Memory != "1g" || cfg.Sandbox.CPUs != "2" || cfg.Sandbox.PidsLimit != 256 || cfg.Sandbox.Image != "custom/node:1.0" {
		t.Fatalf("unexpected sandbox config: %#v", cfg.Sandbox)
	}
	timeout, err := cfg.ParseTimeout()
	if err != nil || timeout != 10*time.Minute {
		t.Fatalf("expected 10m timeout, got %v (%v)", timeout, err)
	}
	if len(cfg.Network.AllowedHosts) != 2 {
		t.Fatalf("expected 2 allowed hosts, got %#v", cfg.Network.AllowedHosts)
	}
	if !cfg.Policy.BlockOnMedium {
		t.Fatal("expected BlockOnMedium to be true")
	}
	if cfg.OSVEnabled() {
		t.Fatal("expected OSVEnabled to be false")
	}
}

func TestLoadInvalidTimeoutFails(t *testing.T) {
	t.Setenv("SAFERUN_CONFIG", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"sandbox":{"timeout":"not-a-duration"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}
