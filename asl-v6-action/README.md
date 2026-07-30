# ASL V6 AI Security PR Auditor Action

This GitHub Action integrates the **ASL V6 AI Infrastructure & LLM Security Platform** directly into your CI/CD pipeline.

Instead of requiring developers to remember to run the ASL V6 auditor locally before pushing code, this action automatically:
- Scans **only the changed files** in the Pull Request to ensure fast CI execution.
- Verifies raw findings using the **Verification Gauntlet** to reduce static false positives.
- Posts **verified findings as inline PR comments** right on the vulnerable lines of code.
- Synthesizes and suggests a custom secure code patch using deterministic offline reasoning.
- Generates a **SARIF report** that can be uploaded to GitHub Advanced Security.
- Optionally fails the CI build if verified **High** or **Critical** severity issues are introduced on added lines.

## One-Line Setup

To start securing your AI infrastructure on every Pull Request, add the following step to your GitHub Actions workflow:

```yaml
name: ASL V6 Security Scan

on: [pull_request]

jobs:
  asl-v6-scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write # Required to post inline PR comments
      security-events: write # Required to upload SARIF to GitHub Security
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: ASL V6 Auto-Auditor
        uses: sivaadityacoder/asl-v6/asl-v6-action@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_high_severity: 'true'
```

## Inputs

| Name | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `github_token` | Yes | N/A | The standard GitHub token (`${{ secrets.GITHUB_TOKEN }}`) needed to fetch the PR diff and post inline comments. |
| `fail_on_high_severity` | No | `true` | Fail when an added PR line introduces a verified High or Critical finding. |

## Workflow

1. **Developer opens a Pull Request.**
2. GitHub Action triggers automatically.
3. **ASL V6** analyzes only the changed files.
4. **Verified findings appear as inline PR comments**, suggesting code patches.
5. Developer fixes the issues before merging.

*Secure your agents, vector databases, and LLM implementations without disrupting developer velocity.*
