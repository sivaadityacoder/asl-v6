# ASL V6.1 — Open-Source AI Vulnerability Scanner

![Version](https://img.shields.io/badge/version-6.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

![ASL V6 Demo](docs/demo.gif)

**Author:** Siva Aditya Panuganti (Security Researcher)  
**Track Record:** 6+ CVEs and GHSAs in production AI systems (AutoGPT, FlowiseAI, LLaMmlein, LangGraph MsgPack RCE) via responsible disclosure to BSI Germany, CERT-EE, and GitHub Security.

---

## Quick Start

```bash
pip install git+https://github.com/sivaadityacoder/asl-v6.git
asl-v6 /path/to/your/project --fail-on high
```

## Table of Contents
- [What It Does](#what-it-does)
- [Quick Start](#quick-start)
- [Installation & Usage](#installation--usage)
- [Trusted By](#trusted-by)
- [Verified Execution Benchmark](#verified-execution-benchmark)
- [CI/CD Pull Request Gate](#cicd-pull-request-gate)
- [Community and Pro Editions](#community-and-pro-editions)
- [Stable and Experimental Scope](#stable-and-experimental-scope)
- [Separate Advisory Services](#separate-advisory-services)

---

## What It Does

ASL V6.1 is an automated vulnerability scanner for Python, JavaScript, TypeScript, and AI agent codebases. It combines contextual source analysis with confidence-based validation to identify actionable security risks.

### Technical Capabilities
1. **10 Security Scanners:** Analyzes code for OWASP Top 10 LLM and Agent vulnerabilities, including prompt injection sinks, goal hijacking, unsafe code execution (`eval`/`exec`), and tool abuse.
2. **AST Contextual Filtering:** Parses Python syntax trees to ignore test suites, mock files, and docstrings. This eliminates around 98% of false positive alerts.
3. **CI Severity Gates:** Can return a failing exit code for Low, Medium, High, or Critical validated findings.
4. **Remediation Patch Generation (Optional):** Generates structured code fixes and patch suggestions. This is opt-in with `--remediate`; it works offline or can use an NVIDIA developer endpoint when configured.

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

## Trusted By

- [Aditya Security Labs](https://adityasecuritylabs.tech) — Production AI security assessments
- [Your next company here] — [Contact us](mailto:adityasecuritylabs@gmail.com)

---

## Verified Execution Benchmark

Tested on real filesystem repositories:

| Repository | Files Scanned | Raw Alerts | Validated True Positives | False Positive Reduction | Runtime Verification |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **LangGraph** | 513 | 606 | **13 high-confidence findings** | **97.9%** | Historical benchmark |
| **ASL V6 Engine** | 7 | 48 | **0 high-confidence findings** | **100.0%** | Historical benchmark |

---

## CI/CD Pull Request Gate

You can use the included GitHub Actions workflow (`asl_v6_ci_cd_action.yml`) to automatically scan pull requests for security flaws during your CI/CD build process.

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

## Stable and Experimental Scope

- **✅ Stable:** Local repository scanning, 10 specialist scanners, CLI gates, GitHub Action PR audit.
- **🔬 Experimental:** Live container/DAST probing (research-only, not enabled by default). Legacy bug-bounty prototypes are not part of the public distribution.
- Only test targets you own or have explicit authorization to assess.

---

## Separate Advisory Services

Pro is the recurring software subscription. Manual security research and consulting are separate services:
* **Advisory Retainer ($2,500 / month):** Monthly architecture review, manual vulnerability discovery, and remediation pull requests written directly for your codebase.
* **Emergency Security Assessment ($5,000 fixed):** 1-week pre-launch code audit or post-incident review with proof-of-concept exploits and remediation guidance.
* **EU AI Act Technical Documentation ($3,500 - $5,000 fixed):** Technical robustness testing and adversarial documentation for European compliance.

**Contact:** adityasecuritylabs@gmail.com | [GitHub Profile](https://github.com/sivaadityacoder)

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=sivaadityacoder/asl-v6&type=Date)](https://star-history.com/#sivaadityacoder/asl-v6&Date)
