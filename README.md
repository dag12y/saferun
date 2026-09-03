# SafeRun

SafeRun is a security-focused package installation tool that analyzes package installation behavior inside an isolated sandbox before allowing the package to be installed on the host system.

The initial version focuses on npm packages and uses Docker as the sandbox runtime.

## How It Works

Instead of installing a package directly on the host:

```bash
npm install lodash
```

SafeRun aims to provide:

```bash
saferun npm install lodash
```

The package is first installed inside an isolated environment. SafeRun will eventually monitor filesystem access, network activity, process execution, and other potentially dangerous behavior.

After analysis, SafeRun will present a security report and ask the user whether the package should be installed on the host.

## Status

### Completed

- [x] Go project initialized
- [x] CLI entry point created
- [x] Docker sandbox image created
- [x] Go CLI can execute Docker containers
- [x] Node.js runtime available inside sandbox
- [x] npm available inside sandbox
- [x] Package installation tested inside disposable container

### In Progress

- [ ] Harden Docker sandbox
- [ ] Implement package command parsing
- [ ] Implement package metadata analysis
- [ ] Detect npm lifecycle scripts
- [ ] Monitor filesystem activity
- [ ] Monitor process execution
- [ ] Monitor network activity
- [ ] Implement behavior analysis
- [ ] Implement risk scoring
- [ ] Generate security reports
- [ ] Add user approval flow
- [ ] Ensure analyzed artifact matches installed artifact

### Future

- [ ] Python/pip support
- [ ] Additional package managers
- [ ] Package reputation
- [ ] Vulnerability intelligence
- [ ] Advanced sandboxing
- [ ] Optional cloud analysis

## Architecture

```text
                    SafeRun CLI
                         |
                         v
                  Command Parser
                         |
                         v
                  Package Manager
                     Adapter
                         |
                         v
                  Sandbox Manager
                         |
                         v
                  Docker Container
                         |
              +----------+----------+
              |          |          |
              v          v          v
          Filesystem  Network   Processes
              |          |          |
              +----------+----------+
                         |
                         v
                  Behavior Analyzer
                         |
                         v
                    Risk Engine
                         |
                         v
                     Report
                         |
                         v
                   User Approval
```

## Project Structure

```text
saferun/
├── cmd/
│   └── saferun/
│       └── main.go
├── internal/
│   ├── analyzer/
│   ├── cli/
│   ├── monitor/
│   ├── package_manager/
│   ├── report/
│   ├── risk/
│   └── sandbox/
│       └── docker.go
├── pkg/
├── sandbox/
│   └── images/
│       └── node/
│           └── Dockerfile
├── tests/
├── docs/
├── go.mod
└── README.md
```

## Development

### Requirements

- Linux or WSL
- Go
- Docker
- Node.js and npm
- Git

### Run

```bash
go run ./cmd/saferun
```

## Setup

SafeRun requires Docker.

After installing SafeRun, run:

```bash
saferun setup
```

This verifies Docker and prepares the SafeRun sandbox image.

After setup:

```bash
saferun npm install express
```

## Install

Install the configured SafeRun release for Linux or macOS:

```bash
curl -fsSL https://YOUR-DOMAIN/install.sh | sh
```

`YOUR-DOMAIN` is temporary and will be replaced when the SafeRun website is available. The installer downloads the matching GitHub Release binary, verifies its SHA-256 checksum, and installs it to `~/.local/bin/saferun` without requiring Go or a repository checkout. Set `SAFERUN_VERSION` to install a different release.

If `~/.local/bin` is not in your `PATH`, the installer prints the command needed to add it. SafeRun requires Docker for sandboxed package analysis; the installer does not install Docker.

### Manual GitHub Release Installation

Download the binary for your platform and `SHA256SUMS` from the [SafeRun v1.0.2 release](https://github.com/dag12y/saferun/releases/tag/v1.0.2). Verify the binary against `SHA256SUMS`, then install it as `~/.local/bin/saferun`:

```bash
mkdir -p ~/.local/bin
install -m 0755 saferun-linux-amd64 ~/.local/bin/saferun
```

After either installation method:

```bash
saferun setup
saferun npm install lodash
```

SafeRun analyzes the package in an isolated Docker sandbox before allowing the host-side installation.

### Build

```bash
go build -o saferun ./cmd/saferun
```
## Releases

SafeRun provides prebuilt release binaries for:

- Linux
- macOS
- Windows

The release process publishes cross-platform binaries and SHA256 checksums for each tagged version.
