# Changelog

## 6.1.2 - 2026-07-30

### Changed

- LLM logging detection now analyzes Python logging-call expressions instead of matching sensitive words inside literal messages.
- Goal-injection detection requires a direct goal/objective/instruction assignment with evidence of untrusted input.
- Pull-request documentation paths now recognize common `docs_src`, documentation, tutorial, and sample directory names.

### Fixed

- Stop treating internal asyncio/executor task assignments as agent goal hijacking.
- Stop treating `capture_output=True` as LLM-generated data passed to `subprocess`.
- Stop reporting type-only, status-only, and static compatibility log messages as raw model-data leakage.
- Lower public/anonymous/publishable client-key signals below validation confidence while preserving real secret-key detections.
- Preserve detections for serialized model responses, raw MCP protocol messages, and unsafe deserialization.

### Validation

- Scanned pinned commits of OpenAI Agents Python, MCP Python SDK, and LangGraph: 2,235 source files, zero scanner errors.
- Verified `--fail-on high` exits 0 for Medium-only reports and exits 1 for a Critical unsafe-deserialization finding.

## 6.1.1 - 2026-07-30

### Changed

- PR reviews and severity gates now apply only to findings introduced on added diff lines.
- PR remediation is forced to deterministic offline mode so CI never sends source context to an external model endpoint.
- Benchmark reports are written below the caller's output root and default runs scan the current directory.

### Fixed

- Reject changed-file symlinks, workspace escapes, and oversized files in the PR action.
- Continue running remaining specialist agents when one scanner fails on a changed file.
- Scan JSX and TSX pull-request changes consistently with the stable CLI.
- Attach accurate line numbers to every specialist-agent finding.
- Confine remediation context reads to regular files inside the target repository.
- Require an explicit sandbox proof marker instead of treating arbitrary `uid=` output as exploitation.
- Correct the benchmark and standalone DAST proof snippets so they execute a valid runtime probe.
- Validate sandbox timeout and image configuration before invoking Docker.

## 6.1.0 - 2026-07-30

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
