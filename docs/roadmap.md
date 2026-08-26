# SafeRun Roadmap

This roadmap tracks the planned development of SafeRun from the initial Docker-backed prototype to broader package-manager support and deeper analysis.

## Phase 0 — Foundation

- [x] Initialize Go module
- [x] Create CLI
- [x] Create Docker sandbox image
- [x] Execute Docker from Go
- [x] Execute npm inside sandbox
- [x] Install a test package inside disposable container

## Phase 1 — Sandbox Hardening

- [ ] Disable unnecessary Linux capabilities
- [ ] Add `no-new-privileges`
- [ ] Restrict network access
- [ ] Add filesystem restrictions
- [ ] Add resource limits
- [ ] Investigate seccomp
- [ ] Investigate AppArmor

## Phase 2 — Package Manager Layer

- [ ] Parse SafeRun commands
- [ ] Create package-manager interface
- [ ] Implement npm adapter
- [ ] Resolve package versions
- [ ] Capture package integrity information
- [ ] Inspect package lifecycle scripts

## Phase 3 — Static Analysis

- [ ] Analyze package metadata
- [ ] Detect install scripts
- [ ] Detect suspicious shell commands
- [ ] Detect suspicious URLs
- [ ] Detect obfuscated code
- [ ] Detect native executables
- [ ] Analyze dependency tree

## Phase 4 — Dynamic Analysis

- [ ] Filesystem monitoring
- [ ] Process monitoring
- [ ] Network monitoring
- [ ] Syscall monitoring
- [ ] Environment access monitoring
- [ ] Record sandbox events

## Phase 5 — Risk Engine

- [ ] Define security events
- [ ] Create severity levels
- [ ] Implement scoring
- [ ] Explain risk decisions
- [ ] Add confidence score

## Phase 6 — User Experience

- [ ] Human-readable terminal report
- [ ] Detailed report mode
- [ ] User approval
- [ ] Safe installation
- [ ] Exact artifact verification

## Phase 7 — Python

- [ ] pip adapter
- [ ] Python package build isolation
- [ ] Python-specific static analysis
- [ ] Python runtime analysis

## Phase 8 — Advanced Features

- [ ] Package reputation
- [ ] Known malicious package database
- [ ] Vulnerability intelligence
- [ ] Optional cloud analysis
- [ ] CI/CD integration
