# Changelog

## 6.1.0 - Unreleased

### Added

- Installable `asl-v6` command with `--help` and `--version` support.
- Reusable `scan_repository()` API for integrations and automated tests.
- Configurable confidence, file-size, report-output, remediation, and CI failure options.
- Automated tests covering file selection, real scanner execution, report generation, and severity gates.
- Community/Pro edition status with the full local scanner retained in Community.

### Changed

- V6.1 officially supports local repository scanning as its stable workflow.
- Generated directories, symlinks, unsupported files, and oversized source files are skipped.
- Remediation synthesis is opt-in for predictable offline execution.
- Reports identify the exact engine version used.
- Replaced the legacy consulting-package key matcher with a safe Community/Pro entitlement model.

### Fixed

- Preserve real findings in YAML/JSON and production files whose names merely contain `test`.
- Exclude generated dependency trees consistently during target profiling.
- Execute the caller-provided Docker proof snippet with a read-only, capability-dropped container.
- Paginate GitHub pull-request files and restrict inline review comments to added diff lines.
- Report output and optional-discovery dependency errors cleanly from the CLI.

### Experimental

- The bug-bounty hunter scripts and live DAST/container probing remain research prototypes and are not part of the stable V6.1 CLI.
