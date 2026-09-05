# Contributing to SafeRun

Thanks for helping improve SafeRun. Keep changes focused, explain security-relevant decisions, and preserve the project's goal of making package installation safer without hiding important behavior from users.

## Clone the Repository

```bash
git clone https://github.com/dag12y/saferun.git
cd saferun
```

## Development Setup

Install Go 1.25 or later, Docker, Node.js, npm, and Git. Build or run SafeRun from the repository root. To prepare the local sandbox:

```bash
go run ./cmd/saferun setup
```

## Tests and Builds

Run the full Go test suite:

```bash
go test ./...
```

Build the CLI:

```bash
go build ./cmd/saferun
```

Before opening a pull request, also run `gofmt` on changed Go files and verify the relevant CLI behavior with Docker available.

## Code Style

- Follow standard Go formatting and idioms.
- Keep changes small and focused on one problem.
- Prefer clear errors and explicit security decisions.
- Add or update tests for behavior changes.
- Do not weaken sandboxing, verification, audit logging, or policy enforcement without documenting the security tradeoff.
- Do not include credentials, private package data, or destructive test fixtures.

## Pull Requests

1. Create a focused branch from the default branch.
2. Add tests and documentation for user-visible changes.
3. Run the test suite and build locally.
4. Describe the problem, solution, security impact, and validation in the pull request.
5. Keep unrelated formatting or refactoring out of the change.

Maintainers may request revisions, additional tests, or security review before merging.
