"""Stable command-line interface for the ASL V6.1 repository scanner."""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from v6_ai_infra_security import (
    LLMSecurityReasoningEngine,
    SecurityReportGenerator,
    TargetProfiler,
    VerificationGauntlet,
)
from v6_specialist_agents import ALL_SPECIALIST_AGENTS
from v6_subscription_engine import SubscriptionManager
from v6_version import __version__

SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml"}
EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "logs",
    "node_modules",
    "reports",
    "vendor",
}
SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass(frozen=True)
class ScanResult:
    target: Path
    files_scanned: int
    scan_errors: int
    raw_findings: int
    validated_findings: tuple[dict, ...]
    markdown_report: Path
    json_report: Path


def iter_source_files(
    root: Path,
    *,
    max_file_bytes: int = 2_000_000,
    excluded_directories: set[str] | None = None,
) -> Iterable[Path]:
    """Yield supported source files while skipping generated and oversized content."""
    if max_file_bytes < 0:
        raise ValueError("maximum file size must not be negative")
    excluded = EXCLUDED_DIRECTORIES if excluded_directories is None else excluded_directories
    for candidate in root.rglob("*"):
        try:
            relative_parts = candidate.relative_to(root).parts
        except ValueError:
            continue
        if any(part in excluded for part in relative_parts):
            continue
        try:
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and candidate.suffix.lower() in SUPPORTED_SUFFIXES
                and candidate.stat().st_size <= max_file_bytes
            ):
                yield candidate
        except OSError:
            continue


def scan_repository(
    target: str | Path,
    *,
    confidence_threshold: int = 65,
    output_root: str | Path = ".",
    max_file_bytes: int = 2_000_000,
    remediate: bool = False,
) -> ScanResult:
    """Scan a local repository and write Markdown and JSON reports."""
    target_path = Path(target).expanduser().resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"target does not exist: {target_path}")
    if not target_path.is_dir():
        raise NotADirectoryError(f"target must be a directory: {target_path}")
    if not 0 <= confidence_threshold <= 100:
        raise ValueError("confidence threshold must be between 0 and 100")

    source_files = sorted(iter_source_files(target_path, max_file_bytes=max_file_bytes))
    raw_findings: list[dict] = []
    scan_errors = 0

    for source_file in source_files:
        try:
            content = source_file.read_text(encoding="utf-8", errors="ignore")
            relative_path = str(source_file.relative_to(target_path))
            for agent_class in ALL_SPECIALIST_AGENTS:
                try:
                    raw_findings.extend(agent_class().analyze(content, relative_path))
                except Exception:
                    scan_errors += 1
        except (OSError, UnicodeError, ValueError):
            scan_errors += 1

    profile = TargetProfiler().profile_repository(target_path)
    gauntlet_results = VerificationGauntlet(
        confidence_threshold=confidence_threshold,
        base_path=target_path,
    ).verify(raw_findings)
    gauntlet_results["scan_summary"] = {
        "files_scanned": len(source_files),
        "scan_errors": scan_errors,
    }

    validated = gauntlet_results["validated_findings"]
    if remediate:
        reasoning_engine = LLMSecurityReasoningEngine()
        for finding in validated[:5]:
            reasoning_engine.reason_and_remediate(finding, target_path)

    output_path = Path(output_root).expanduser().resolve()
    markdown_report, json_report = SecurityReportGenerator().generate(
        profile,
        gauntlet_results,
        output_path,
    )

    return ScanResult(
        target=target_path,
        files_scanned=len(source_files),
        scan_errors=scan_errors,
        raw_findings=len(raw_findings),
        validated_findings=tuple(validated),
        markdown_report=markdown_report,
        json_report=json_report,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asl-v6",
        description="Scan a local AI/LLM repository for high-confidence security issues.",
    )
    parser.add_argument("target", nargs="?", help="local repository directory to scan")
    parser.add_argument("--version", action="version", version=f"ASL V6 {__version__}")
    parser.add_argument(
        "--subscription-status",
        action="store_true",
        help="show Community/Pro edition status without running a scan",
    )
    parser.add_argument(
        "--confidence",
        type=int,
        default=65,
        metavar="0-100",
        help="minimum confidence required for a validated finding (default: 65)",
    )
    parser.add_argument(
        "--output-root",
        default=".",
        help="directory under which the reports/ folder is created (default: current directory)",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=2.0,
        help="skip individual files larger than this value (default: 2)",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="add remediation synthesis for up to five validated findings",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="return exit code 1 when a finding meets this severity (default: none)",
    )
    return parser


def _threshold_reached(findings: Sequence[dict], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    minimum = SEVERITY_RANK[fail_on.title()]
    return any(SEVERITY_RANK.get(str(finding.get("severity", "Info")), 0) >= minimum for finding in findings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subscription_status:
        SubscriptionManager().display_status()
        return 0
    if not args.target:
        parser.error("the following arguments are required: target")
    if not 0 <= args.confidence <= 100:
        parser.error("--confidence must be between 0 and 100")
    if not math.isfinite(args.max_file_mb) or args.max_file_mb <= 0:
        parser.error("--max-file-mb must be a finite value greater than zero")

    try:
        result = scan_repository(
            args.target,
            confidence_threshold=args.confidence,
            output_root=args.output_root,
            max_file_bytes=int(args.max_file_mb * 1_000_000),
            remediate=args.remediate,
        )
    except (OSError, ValueError) as error:
        parser.exit(2, f"asl-v6: error: {error}\n")

    print(
        f"Scanned {result.files_scanned} files; found "
        f"{len(result.validated_findings)} validated findings "
        f"({result.scan_errors} scan errors)."
    )
    print(f"Markdown report: {result.markdown_report}")
    print(f"JSON report: {result.json_report}")

    return 1 if _threshold_reached(result.validated_findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
