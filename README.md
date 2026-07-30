# ASL V6.1 — Open-Source AI Vulnerability Scanner

> **V6.1 release candidate:** local repository scanning is the stable, supported workflow. Live container and DAST probing remain experimental research tools.

**Author:** Siva Aditya Panuganti (Security Researcher)  
**Track Record:** 6+ CVEs and GHSAs in production AI systems (AutoGPT, FlowiseAI, LLaMmlein, LangGraph MsgPack RCE) via responsible disclosure to BSI Germany, CERT-EE, and GitHub Security.

---

## What It Does

ASL V6.1 is an automated vulnerability scanner for Python, JavaScript, TypeScript, and AI agent codebases. It combines contextual source analysis with confidence-based validation to identify actionable security risks.

### Technical Capabilities
1. **10 Security Scanners:** Analyzes code for OWASP Top 10 LLM and Agent vulnerabilities, including prompt injection sinks, goal hijacking, unsafe code execution (`eval`/`exec`), and tool abuse.
2. **AST Contextual Filtering:** Parses Python syntax trees to ignore test suites, mock files, and docstrings. This eliminates around 98% of false positive alerts.
3. **CI Severity Gates:** Can return a failing exit code for Low, Medium, High, or Critical validated findings.
4. **Remediation Patch Generation (Optional):** Generates structured code fixes and patch suggestions. This is opt-in with `--remediate`; it works offline or can use an NVIDIA developer endpoint when configured.

---

## Community and Pro Editions

The complete local scanner is free and open source under the MIT License. A paid **ASL V6 Pro** subscription adds managed team and organization services; it does not remove or disable Community functionality.

| Capability | Community (MIT) | Pro Subscription |
| :--- | :---: | :---: |
| Ten local specialist scanners and verification gauntlet | ✅ | ✅ |
| Markdown/JSON reports and CI severity exit codes | ✅ | ✅ |
| Offline remediation and bring-your-own model key | ✅ | ✅ |
| Organization policy packs and shared configuration | — | ✅ |
| Central dashboard, scan history, and risk trends | — | ✅ |
| Scheduled scans and managed PR/SARIF integration | — | ✅ |
| Compliance exports and priority support | — | ✅ |

Community execution is local and does not require a subscription key. Pro is a hosted/managed layer whose entitlement must be verified by the subscription service. See [PRO.md](PRO.md) for the product boundary and launch requirements.

---

## Verified Execution Benchmark

### Real OSS validation

V6.1.2 was exercised against pinned public GitHub commits using the packaged CLI. Findings are static review signals, not claims of confirmed vulnerabilities.

| Target | Commit | Files | Validated signals | Scan errors | `--fail-on high` |
| :--- | :--- | ---: | ---: | ---: | :---: |
| [OpenAI Agents Python](https://github.com/openai/openai-agents-python) | [`992abf7`](https://github.com/openai/openai-agents-python/commit/992abf763d24881bab55663de6a93cf58f1c6118) | 876 | 5 Medium | 0 | Exit 0 |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) | [`a4f4ccd`](https://github.com/modelcontextprotocol/python-sdk/commit/a4f4ccd091138771535e17191123f20b30fda68e) | 846 | 5 Medium | 0 | Exit 0 |
| [LangGraph](https://github.com/langchain-ai/langgraph) | [`4134145`](https://github.com/langchain-ai/langgraph/commit/41341457342327166d72fc11952ab28fb61ec0bf) | 513 | 1 Critical | 0 | Exit 1 |

The remaining signals were source-reviewed: serialized model-response logging, raw MCP protocol-message logging, and an explicit pickle fallback. Exact results can change as upstream repositories evolve.

---

## Installation & Usage

### 1. Install Dependencies
```bash
git clone https://github.com/sivaadityacoder/asl-v6.git
cd asl-v6
pip install -r requirements.txt
pip install -e .
```

### 2. Scan a Codebase
```bash
asl-v6 /path/to/your/project
```

Useful release options:

```bash
# Show the installed release
asl-v6 --version

# Show Community/Pro status
asl-v6 --subscription-status

# Fail CI when a validated High or Critical issue is found
asl-v6 /path/to/project --fail-on high

# Change confidence and add remediation suggestions
asl-v6 /path/to/project --confidence 75 --remediate
```

### 3. Run the Benchmark
```bash
python3 v6_ai_benchmarks.py /path/to/repo1 /path/to/repo2
```

---

## CI/CD Pull Request Gate

You can use the included GitHub Actions workflow (`asl_v6_ci_cd_action.yml`) to automatically scan pull requests for security flaws during your CI/CD build process.
The repository also remains usable as a root composite action with
`uses: sivaadityacoder/asl-v6@main`; see [`asl-v6-action/README.md`](asl-v6-action/README.md).

## Stable and Experimental Scope

- **Stable:** local repository profiling, ten specialist scanners, verification gauntlet, Markdown/JSON reports, and CLI severity gates suitable for CI.
- **Experimental:** live container/DAST probing. Legacy bug-bounty prototypes are not part of the public distribution.
- **Release candidate:** the bundled GitHub PR-comment action still needs end-to-end validation before a versioned release.
- Only test targets you own or have explicit authorization to assess.

---

## Separate Advisory Services

Pro is the recurring software subscription. Manual security research and consulting are separate services:
* **Advisory Retainer ($2,500 / month):** Monthly architecture review, manual vulnerability discovery, and remediation pull requests written directly for your codebase.
* **Emergency Security Assessment ($5,000 fixed):** 1-week pre-launch code audit or post-incident review with proof-of-concept exploits and remediation guidance.
* **EU AI Act Technical Documentation ($3,500 - $5,000 fixed):** Technical robustness testing and adversarial documentation for European compliance.

**Contact:** adityasecuritylabs@gmail.com | [GitHub Profile](https://github.com/sivaadityacoder)
