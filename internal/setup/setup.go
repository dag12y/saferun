package setup

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const (
	DefaultDockerTimeout = 10 * time.Second
	DefaultPullTimeout   = 120 * time.Second
)

func DockerTimeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultDockerTimeout)
}

func PullTimeoutContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultPullTimeout)
}

func withTimeoutIfNeeded(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), timeout)
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

type DockerStatus struct {
	Installed     bool
	DaemonRunning bool
}

type DockerClient interface {
	LookPath(file string) (string, error)
	Info(ctx context.Context) error
	ImageInspect(ctx context.Context, image string) error
	Pull(ctx context.Context, image string) ([]byte, error)
}

type RealDocker struct{}

func (RealDocker) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (RealDocker) Info(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "info")
	return cmd.Run()
}

func (RealDocker) ImageInspect(ctx context.Context, image string) error {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", image)
	return cmd.Run()
}

func (RealDocker) Pull(ctx context.Context, image string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	return cmd.CombinedOutput()
}

var ErrImageMissing = errors.New("sandbox image missing")

func CheckDockerAvailability(ctx context.Context, client DockerClient) (DockerStatus, error) {
	if client == nil {
		client = RealDocker{}
	}
	ctx, cancel := withTimeoutIfNeeded(ctx, DefaultDockerTimeout)
	defer cancel()

	if _, err := client.LookPath("docker"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return DockerStatus{Installed: false}, nil
		}
		return DockerStatus{}, err
	}

	status := DockerStatus{Installed: true}
	if err := client.Info(ctx); err != nil {
		return status, nil
	}

	status.DaemonRunning = true
	return status, nil
}

func CheckSandboxImage(ctx context.Context, client DockerClient, image string) (bool, error) {
	if client == nil {
		client = RealDocker{}
	}
	ctx, cancel := withTimeoutIfNeeded(ctx, DefaultDockerTimeout)
	defer cancel()
	if err := client.ImageInspect(ctx, image); err == nil {
		return true, nil
	}
	return false, ErrImageMissing
}

func EnsureSandboxImage(ctx context.Context, client DockerClient, image string) (bool, error) {
	if client == nil {
		client = RealDocker{}
	}
	ctx, cancel := withTimeoutIfNeeded(ctx, DefaultPullTimeout)
	defer cancel()

	if available, err := CheckSandboxImage(ctx, client, image); err == nil && available {
		return true, nil
	}

	if _, err := client.Pull(ctx, image); err != nil {
		return false, fmt.Errorf("pull %s: %w", image, err)
	}

	if err := client.ImageInspect(ctx, image); err != nil {
		return false, fmt.Errorf("verify %s after pull: %w", image, err)
	}

	return true, nil
}

func RunWithDocker(ctx context.Context, client DockerClient, image string) error {
	if client == nil {
		client = RealDocker{}
	}
	ctx, cancel := withTimeoutIfNeeded(ctx, DefaultDockerTimeout)
	defer cancel()

	status, err := CheckDockerAvailability(ctx, client)
	if err != nil {
		return fmt.Errorf("check docker availability: %w", err)
	}
	if !status.Installed {
		return fmt.Errorf("docker is not installed")
	}
	if !status.DaemonRunning {
		return fmt.Errorf("docker daemon is not running")
	}

	if _, err := EnsureSandboxImage(ctx, client, image); err != nil {
		return fmt.Errorf("prepare sandbox image: %w", err)
	}
	return nil
}

func DockerNotConfiguredMessage() string {
	return "SafeRun sandbox is not configured.\n\nRun:\n\n  saferun setup\n\nbefore installing packages."
}
