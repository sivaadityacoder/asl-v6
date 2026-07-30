import json
import logging
import os
import re
import sys
from pathlib import Path

import requests

# Set up path to import ASL V6 core modules from the parent directory
_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(_ROOT))

from v6_ai_infra_security import LLMSecurityReasoningEngine, VerificationGauntlet
from v6_specialist_agents import ALL_SPECIALIST_AGENTS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
GITHUB_API_TIMEOUT = 20
MAX_SOURCE_BYTES = 2_000_000
SUPPORTED_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".yaml", ".yml", ".json"}

def get_pr_files(github_token, repo, pr_number):
    """Fetch changed files for a PR."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    files = []
    page = 1
    while True:
        response = requests.get(
            url,
            headers=headers,
            params={"per_page": 100, "page": page},
            timeout=GITHUB_API_TIMEOUT,
        )
        response.raise_for_status()
        batch = response.json()
        if not isinstance(batch, list):
            raise ValueError("GitHub PR files response was not a list")
        files.extend(batch)
        if len(batch) < 100:
            return files
        page += 1

def post_pr_review(github_token, repo, pr_number, commit_id, comments):
    """Post inline comments as a PR review."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {
        "commit_id": commit_id,
        "event": "COMMENT",
        "comments": comments
    }
    response = requests.post(
        url,
        headers=headers,
        json=data,
        timeout=GITHUB_API_TIMEOUT,
    )
    response.raise_for_status()


def added_lines_from_patch(patch):
    """Return new-file line numbers represented by additions in a unified diff."""
    added_lines = set()
    new_line = None
    for line in (patch or "").splitlines():
        header = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if header:
            new_line = int(header.group(1))
            continue
        if new_line is None or line.startswith("\\ No newline at end of file"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.add(new_line)
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            new_line += 1
    return added_lines


def resolve_changed_file(workspace: Path, filename: str) -> Path | None:
    """Resolve a changed source file without following paths outside the workspace."""
    if not isinstance(filename, str) or not filename:
        return None
    workspace = workspace.resolve()
    candidate = workspace / filename
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        if (
            not resolved.is_relative_to(workspace)
            or not resolved.is_file()
            or resolved.stat().st_size > MAX_SOURCE_BYTES
        ):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved


def findings_on_added_lines(findings, added_lines_by_file):
    """Keep only findings introduced by the pull request diff."""
    result = []
    for finding in findings:
        try:
            line = int(finding.get("line_number", 0))
        except (TypeError, ValueError):
            continue
        if line in added_lines_by_file.get(finding.get("file_path"), set()):
            result.append(finding)
    return result

def generate_sarif(findings, repo_path, output_file="asl-v6-results.sarif"):
    """Generate SARIF JSON from ASL V6 findings."""
    rules = []
    results = []
    rule_ids_seen = set()

    for finding in findings:
        rule_id = str(finding.get("owasp_llm_id") or finding.get("category") or "ASL-001")
        if rule_id not in rule_ids_seen:
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": finding.get("category", "General AI Security Issue")},
                "fullDescription": {"text": finding.get("title", "")},
                "help": {"text": finding.get("remediation", "")},
                "properties": {
                    "tags": ["security", "ai-security", "asl-v6"]
                }
            })
            rule_ids_seen.add(rule_id)

        try:
            start_line = max(1, int(finding.get("line_number", 1)))
        except (TypeError, ValueError):
            start_line = 1

        results.append({
            "ruleId": rule_id,
            "message": {"text": finding.get("description", "Potential vulnerability detected.")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.get("file_path", "")},
                    "region": {
                        "startLine": start_line,
                        "snippet": {"text": finding.get("code_evidence", "")}
                    }
                }
            }]
        })

    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ASL V6 AI Security",
                    "informationUri": "https://adityasecuritylabs.com",
                    "rules": rules
                }
            },
            "results": results
        }]
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
    logging.info(f"Generated SARIF report: {output_file}")

def scan_file_with_agents(file_path: Path, relative_path: str):
    """Run ASL V6 Specialist Agents on a specific file."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError) as error:
        logging.error(f"Error reading {relative_path}: {error}")
        return findings

    for AgentClass in ALL_SPECIALIST_AGENTS:
        try:
            agent = AgentClass()
            findings.extend(agent.analyze(content, relative_path))
        except Exception as error:
            logging.error(
                "Scanner %s failed on %s: %s",
                getattr(AgentClass, "__name__", str(AgentClass)),
                relative_path,
                error,
            )
    return findings

def main():
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        logging.error("GITHUB_TOKEN is missing!")
        sys.exit(1)

    event_path = os.getenv("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        logging.error("GITHUB_EVENT_PATH not found. Are we running in GitHub Actions?")
        sys.exit(1)

    with open(event_path) as f:
        event = json.load(f)

    pr = event.get("pull_request")
    if not pr:
        logging.info("Not a pull request event. Skipping PR inline scan.")
        sys.exit(0)

    repo_name = event.get("repository", {}).get("full_name")
    pr_number = pr.get("number")
    commit_id = pr.get("head", {}).get("sha")
    workspace = Path(os.getenv("GITHUB_WORKSPACE", ".")).resolve()
    if not workspace.is_dir():
        logging.error("GITHUB_WORKSPACE is not a directory: %s", workspace)
        sys.exit(1)

    logging.info(f"Fetching changed files for {repo_name} PR #{pr_number}")
    changed_files = get_pr_files(github_token, repo_name, pr_number)

    all_raw_findings = []
    commentable_lines = {}
    for file_info in changed_files:
        if file_info.get("status") in ("removed",):
            continue

        filename = file_info.get("filename")
        if not filename:
            continue
        file_path = resolve_changed_file(workspace, filename)
        if file_path is None:
            logging.warning("Skipping unsafe, missing, or oversized changed file: %s", filename)
            continue

        if file_path.suffix.lower() in SUPPORTED_SUFFIXES:
            logging.info(f"Scanning changed file: {filename}")
            added_lines = added_lines_from_patch(file_info.get("patch"))
            if not added_lines and file_info.get("status") == "added":
                line_count = len(file_path.read_text(encoding="utf-8", errors="ignore").splitlines())
                added_lines = set(range(1, line_count + 1))
            commentable_lines[filename] = added_lines
            all_raw_findings.extend(scan_file_with_agents(file_path, filename))

    logging.info(f"Detected {len(all_raw_findings)} raw heuristic signals.")

    gauntlet = VerificationGauntlet(confidence_threshold=65, base_path=workspace)
    gauntlet_results = gauntlet.verify(all_raw_findings)
    validated_findings = gauntlet_results.get("validated_findings", [])
    introduced_findings = findings_on_added_lines(validated_findings, commentable_lines)

    logging.info(
        "Validated findings on added lines: %s (%s across complete changed files; false positive reduction: %s%%)",
        len(introduced_findings),
        len(validated_findings),
        gauntlet_results.get("fp_reduction_percentage"),
    )

    # Optional: Reason and remediate the top findings to get a patch
    reasoning_engine = LLMSecurityReasoningEngine(provider="offline")
    for finding in introduced_findings:
        reasoning_engine.reason_and_remediate(finding, workspace)

    generate_sarif(introduced_findings, workspace)

    comments = []
    high_severity_found = False

    for finding in introduced_findings:
        sev = finding.get("severity", "Medium")
        if sev in ("High", "Critical"):
            high_severity_found = True

        # Format the inline comment body
        body = "### 🚨 ASL V6 AI Security Issue Detected\n\n"
        body += f"**{sev} Severity:** {finding.get('title', 'Unknown')}\n"
        body += f"**Category:** `{finding.get('category', 'General')}`\n\n"
        body += f"{finding.get('description', '')}\n\n"

        if "llm_reasoning" in finding:
            llm_r = finding["llm_reasoning"]
            body += f"#### 🛡️ AI Architect Patch\n```python\n{llm_r.get('custom_code_patch', '').strip()}\n```\n"

        finding_path = finding.get("file_path")
        try:
            finding_line = int(finding.get("line_number", 1))
        except (TypeError, ValueError):
            finding_line = 1
        if finding_line in commentable_lines.get(finding_path, set()):
            comments.append({
                "path": finding_path,
                "line": finding_line,
                "side": "RIGHT",
                "body": body,
            })

    if comments:
        logging.info(f"Posting {len(comments)} inline comments to PR.")
        post_pr_review(github_token, repo_name, pr_number, commit_id, comments)

    fail_on_high = os.getenv("FAIL_ON_HIGH_SEVERITY", "true").lower() == "true"
    if high_severity_found and fail_on_high:
        logging.error("Verified High/Critical severity issues were found. Failing the CI gate.")
        sys.exit(1)

    logging.info("ASL V6 Scan complete.")

if __name__ == "__main__":
    main()
