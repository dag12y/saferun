# SafeRun Sandbox Security Model

## Principle

SafeRun executes package installation in an isolated environment and follows a default-deny security model.

## Current Controls

### Capability restriction

All Linux capabilities are dropped:

`--cap-drop=ALL`

### Privilege escalation

Privilege escalation is disabled:

`--security-opt=no-new-privileges`

### Network

The initial sandbox uses:

`--network=none`

Network access will later be implemented through a controlled monitoring architecture.

### Resources

The sandbox has explicit CPU and memory limits.

### Container lifecycle

Containers are disposable and removed after execution using:

`--rm`

## Security Boundary

Docker is currently used as the sandbox boundary.

The project does not currently claim that Docker provides perfect protection against arbitrary malicious code.

The sandbox will be progressively hardened and tested.

## Future Controls

- PID limits
- Read-only root filesystem
- Controlled writable workspace
- Seccomp profile
- AppArmor
- Network monitoring
- Filesystem monitoring
- Process monitoring
