# Security Policy

SafeRun exists to reduce the risk of software supply chain attacks during package installation. Security is treated as a product requirement: sandbox boundaries, package analysis, policy decisions, artifact verification, and audit history should be understandable and reviewable.

## Reporting a Vulnerability

Do not publicly disclose a vulnerability before the maintainers have had an opportunity to investigate and release a fix. Do not open a public GitHub issue for sensitive security reports.

Report security issues privately through the repository's GitHub security advisories feature or by contacting the maintainers through the contact information listed in the repository. Include:

- A clear description of the vulnerability and its impact
- Reproduction steps or a minimal proof of concept
- Affected versions and environment details
- Any suggested mitigation

The maintainers will acknowledge valid reports, investigate them, and coordinate disclosure and remediation with the reporter when appropriate.

## Supported Versions

Security fixes are currently focused on the latest stable release. Users should upgrade to the newest release before reporting or troubleshooting an issue.

| Version        | Supported |
| -------------- | --------- |
| 1.0.x          | Yes       |
| Older releases | No        |

## Security Philosophy

SafeRun is a defense-in-depth tool, not a guarantee that every malicious or vulnerable package will be detected. Keep Docker, the host operating system, Node.js, npm, and SafeRun up to date. Review reports and audit history, and use the security decision as one part of a broader software supply chain security process.
