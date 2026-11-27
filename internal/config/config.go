package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const FileName = ".saferunrc"

// Config holds optional user/project configuration loaded from .saferunrc.
type Config struct {
	Sandbox SandboxConfig `json:"sandbox,omitempty"`
	Network NetworkConfig `json:"network,omitempty"`
	Policy  PolicyConfig  `json:"policy,omitempty"`
	OSV     OSVConfig     `json:"osv,omitempty"`
}

type SandboxConfig struct {
	Memory    string `json:"memory,omitempty"`
	CPUs      string `json:"cpus,omitempty"`
	PidsLimit int    `json:"pids_limit,omitempty"`
	Timeout   string `json:"timeout,omitempty"`
	Image     string `json:"image,omitempty"`
}

type NetworkConfig struct {
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}

type PolicyConfig struct {
	BlockOnMedium bool `json:"block_on_medium,omitempty"`
}

type OSVConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// OSVEnabled returns true unless explicitly disabled in config.
func (c Config) OSVEnabled() bool {
	if c.OSV.Enabled == nil {
		return true
	}
	return *c.OSV.Enabled
}

// ParseTimeout parses Sandbox.Timeout if set.
func (c Config) ParseTimeout() (time.Duration, error) {
	if c.Sandbox.Timeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Sandbox.Timeout)
	if err != nil {
		return 0, fmt.Errorf("invalid sandbox.timeout %q: %w", c.Sandbox.Timeout, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("sandbox.timeout must be positive")
	}
	return d, nil
}

// Load reads .saferunrc from projectDir (or current working directory if empty),
// falling back to ~/.saferunrc if no project-level file exists.
// Missing config files return a zero-value Config without error.
func Load(projectDir string) (Config, error) {
	if envPath := os.Getenv("SAFERUN_CONFIG"); envPath != "" {
		return loadFile(envPath)
	}

	if projectDir == "" {
		if wd, err := os.Getwd(); err == nil {
			projectDir = wd
		}
	}

	if projectDir != "" {
		candidate := filepath.Join(projectDir, FileName)
		if _, err := os.Stat(candidate); err == nil {
			return loadFile(candidate)
		} else if !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("stat %s: %w", candidate, err)
		}
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidate := filepath.Join(home, FileName)
		if _, err := os.Stat(candidate); err == nil {
			return loadFile(candidate)
		} else if !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("stat %s: %w", candidate, err)
		}
	}

	return Config{}, nil
}

func loadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if _, err := cfg.ParseTimeout(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
