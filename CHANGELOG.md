# Changelog

All notable SafeRun releases are documented here.

## v1.1.0

- Added `.saferunrc` configuration support for sandbox limits, allowed network hosts, `block_on_medium`, and OSV checks
- Added OSV (`api.osv.dev`) vulnerability intelligence checks for resolved npm packages
- Added `--format=sarif` (SARIF v2.1.0) output and reusable GitHub Action (`.github/actions/saferun`)
- Added continuous process sampling, IPv6 socket parsing, SHA-256 snapshot hashing, and modified/deleted file behavior analysis
- Added `npm i` and `npm add` command aliases and full transitive dependency rollback in single-package mode
- Fixed versioned/scoped npm registry resolution, semver range verification, risk score accumulation, and rollback path checks

## v1.0.5

- Added colored terminal output
- Improved the audit command
- Added audit clearing

## v1.0.4

- Added the Windows installer
- Added `PATH` integration

## v1.0.3

- Added CLI help and version support

## v1.0.2

- Initial public release improvements
