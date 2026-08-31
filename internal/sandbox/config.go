package sandbox

import "time"

type Config struct {
	Image     string
	Network   string
	Memory    string
	CPUs      string
	Workspace string
	PidsLimit int
	Timeout   time.Duration
}
