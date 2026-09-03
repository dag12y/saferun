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
