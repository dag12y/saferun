# Changelog

All notable SafeRun releases are documented here.

## v2.0.0

- Resolve a single npm lockfile for sandbox analysis and host installation. Verify the downloaded tarballs and the installed dependency tree before publishing it.
- Disable host lifecycle scripts by default. Use `--allow-host-scripts` and confirm separately to run `npm rebuild` on the host.
- Require verifiable public npm registry artifacts. Local directories, workspaces, npm aliases, git dependencies, standalone tarball URLs, project `.npmrc`, and npm shrinkwrap files are unsupported.
- Return exit code `3` for policy decisions that prevent installation. Machine-readable scans still emit a report on a policy block. Operational errors return `1`.
- Scan direct and transitive npm dependencies with OSV. When checks are enabled, an OSV outage fails the scan.
- Restore the full dependency tree on rollback, including existing transitive packages and npm `.bin` links. Remove lockfiles created by a failed install.
- Harden GitHub Action input handling and validate SARIF before upload. The Action builds SafeRun from its own revision by default and supports an explicit release override.
- Run a real npm and Docker integration test in CI and before release.

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
