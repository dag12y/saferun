package setup

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

type fakeDocker struct {
	installed       bool
	daemonAvailable bool
	imageExists     bool
	pullCalled      bool
	imagePullErr    error
	inspectErr      error
	pullOutput      string
}

func (f *fakeDocker) LookPath(file string) (string, error) {
	if !f.installed {
		return "", exec.ErrNotFound
	}
	return "/usr/bin/docker", nil
}

func (f *fakeDocker) Info(ctx context.Context) error {
	if !f.daemonAvailable {
		return errors.New("daemon unavailable")
	}
	return nil
}

func (f *fakeDocker) ImageInspect(ctx context.Context, image string) error {
	if f.inspectErr != nil {
		return f.inspectErr
	}
	if !f.imageExists {
		return errors.New("image not found")
	}
	return nil
}

func (f *fakeDocker) Pull(ctx context.Context, image string) ([]byte, error) {
	f.pullCalled = true
	if f.imagePullErr != nil {
		return nil, f.imagePullErr
	}
	f.imageExists = true
	if f.pullOutput == "" {
		f.pullOutput = "Downloaded newer image for " + image
	}
	return []byte(f.pullOutput), nil
}

func TestCheckDockerAvailability(t *testing.T) {
	tests := []struct {
		name          string
		runner        *fakeDocker
		wantInstalled bool
		wantDaemon    bool
	}{
		{name: "docker available", runner: &fakeDocker{installed: true, daemonAvailable: true}, wantInstalled: true, wantDaemon: true},
		{name: "docker executable missing", runner: &fakeDocker{installed: false}, wantInstalled: false, wantDaemon: false},
		{name: "docker daemon unavailable", runner: &fakeDocker{installed: true, daemonAvailable: false}, wantInstalled: true, wantDaemon: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := CheckDockerAvailability(context.Background(), tt.runner)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if status.Installed != tt.wantInstalled {
				t.Fatalf("installed = %v, want %v", status.Installed, tt.wantInstalled)
			}
			if status.DaemonRunning != tt.wantDaemon {
				t.Fatalf("daemonRunning = %v, want %v", status.DaemonRunning, tt.wantDaemon)
			}
		})
	}
}

func TestEnsureSandboxImage(t *testing.T) {
	t.Run("image already exists", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: true}
		available, err := EnsureSandboxImage(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !available {
			t.Fatal("expected image to be available")
		}
		if runner.pullCalled {
			t.Fatal("did not expect image pull when image already exists")
		}
	})

	t.Run("image missing pulls successfully", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: false}
		available, err := EnsureSandboxImage(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0")
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if !available {
			t.Fatal("expected image to be available after pull")
		}
		if !runner.pullCalled {
			t.Fatal("expected image pull to be attempted")
		}
	})

	t.Run("image pull fails", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: false, imagePullErr: errors.New("pull failed")}
		_, err := EnsureSandboxImage(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0")
		if err == nil {
			t.Fatal("expected pull failure")
		}
	})

	t.Run("image still missing after pull", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: false, inspectErr: errors.New("still missing")}
		_, err := EnsureSandboxImage(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0")
		if err == nil {
			t.Fatal("expected missing-after-pull failure")
		}
	})
}

func TestRunSetup(t *testing.T) {
	t.Run("successful setup", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: true}
		if err := RunWithDocker(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0"); err != nil {
			t.Fatalf("expected setup to succeed, got %v", err)
		}
	})

	t.Run("docker unavailable", func(t *testing.T) {
		runner := &fakeDocker{installed: false}
		if err := RunWithDocker(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0"); err == nil {
			t.Fatal("expected docker unavailable error")
		}
	})

	t.Run("image setup failure", func(t *testing.T) {
		runner := &fakeDocker{installed: true, daemonAvailable: true, imageExists: false, imagePullErr: errors.New("no auth")}
		if err := RunWithDocker(context.Background(), runner, "docker.io/dag12y/saferun-node:1.0.0"); err == nil {
			t.Fatal("expected image setup failure")
		}
	})
}
