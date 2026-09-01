package sandbox

import "time"

const (
	DefaultRegistry  = "docker.io"
	DefaultImageName = "dag12y/saferun-node"
	DefaultImageTag  = "1.0.0"
	DefaultImage     = DefaultRegistry + "/" + DefaultImageName + ":" + DefaultImageTag
)

type Config struct {
	Image     string
	Network   string
	Memory    string
	CPUs      string
	Workspace string
	PidsLimit int
	Timeout   time.Duration
}

func DefaultConfig() Config {
	return Config{
		Image:     DefaultImage,
		Network:   "bridge",
		Memory:    "512m",
		CPUs:      "1",
		Workspace: "/tmp/saferun-workspace",
		PidsLimit: 128,
		Timeout:   5 * time.Minute,
	}
}
