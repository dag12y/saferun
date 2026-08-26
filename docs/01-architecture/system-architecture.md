# SafeRun System Architecture

## Objective

SafeRun is designed to execute package installation inside an isolated environment before allowing installation on the host machine.

The system is designed around five major stages:

1. Package resolution
2. Sandbox execution
3. Runtime observation
4. Security analysis
5. User approval

## Current Architecture

The current prototype contains:

```text
CLI
 |
 v
Sandbox Manager
 |
 v
Docker
 |
 v
Node.js container
 |
 v
npm
```

The sandbox currently executes npm commands inside a disposable Docker container.

## Target Architecture

```text
User
 |
 | saferun npm install <package>
 v
CLI
 |
 v
Command Parser
 |
 v
NPM Adapter
 |
 +----------------------+
 |                      |
 v                      v
Static Analysis     Package Resolution
 |                      |
 +----------+-----------+
            |
            v
      Sandbox Manager
            |
            v
     Hardened Sandbox
            |
      +-----+-----+
      |     |     |
      v     v     v
   Files  Network Processes
      |     |     |
      +-----+-----+
            |
            v
    Behavior Analyzer
            |
            v
       Risk Engine
            |
            v
      Security Report
            |
            v
      User Approval
            |
       +----+----+
       |         |
       v         v
     Install    Reject
```

## Design Principles

### Isolation

Untrusted package installation should occur outside the host environment.

### Least Privilege

The sandbox should receive only the permissions required for package installation.

### Observability

SafeRun should record security-relevant behavior such as:

- Filesystem access
- Network connections
- Process creation
- Executable downloads
- Shell execution
- Access to sensitive locations

### Explainability

Every risk decision should provide a reason.

Instead of:

```text
Risk: HIGH
```

SafeRun should provide:

```text
Risk: HIGH

Reasons:
- Package executed a shell command.
- Package accessed a sensitive credential file.
- Package created an outbound network connection.
```

### Artifact Integrity

The package analyzed by SafeRun must correspond to the package eventually installed on the host.

## Current Limitations

The current prototype uses a basic Docker container.

It does not yet provide:

- Syscall monitoring
- Network monitoring
- Filesystem monitoring
- Hardened container configuration
- Malicious package detection
- Risk scoring

These will be implemented incrementally.
