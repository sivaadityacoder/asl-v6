import asyncio
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import v6_ai_infra_security
from v6_ai_infra_security import InternetDiscoveryEngine, TargetProfiler, VerificationGauntlet
from v6_cli import _threshold_reached, iter_source_files, main, scan_repository
from v6_dynamic_sandbox import V6DynamicSandboxEngine
from v6_specialist_agents import (
    AgentOrchestrationSecurity,
    ASTContextFilter,
    MCPToolSecurityAnalyst,
    ModelDataPoisoningDetector,
    PromptInjectionHunter,
    RAGSecurityAuditor,
    SensitiveDataLeakageScanner,
)
from v6_subscription_engine import SubscriptionManager, SubscriptionTier


class V61CliTests(unittest.TestCase):
    def test_iter_source_files_excludes_generated_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            (root / "notes.txt").write_text("ignored\n", encoding="utf-8")
            (root / "large.py").write_text("x" * 20, encoding="utf-8")
            generated = root / "node_modules"
            generated.mkdir()
            (generated / "dependency.js").write_text("eval(input)\n", encoding="utf-8")

            files = list(iter_source_files(root, max_file_bytes=15))

            self.assertEqual(files, [root / "app.py"])

    def test_iter_source_files_allows_an_empty_exclusion_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "node_modules"
            generated.mkdir()
            source = generated / "dependency.js"
            source.write_text("eval(input)\n", encoding="utf-8")

            files = list(iter_source_files(root, excluded_directories=set()))

            self.assertEqual(files, [source])

    def test_test_file_detection_uses_path_components_not_substrings(self):
        expected = {
            "tests/app.py": True,
            "docs/app.py": True,
            "config.yaml": False,
            "src/contest_utils.py": False,
            "src/latest_model.py": False,
        }
        for file_path, is_test in expected.items():
            with self.subTest(file_path=file_path):
                self.assertIs(ASTContextFilter.is_test_file(file_path), is_test)

    def test_ci_expressions_are_not_prompt_injection_payloads(self):
        findings = PromptInjectionHunter().analyze(
            "token: ${{ secrets.GITHUB_TOKEN }}\n",
            "action.yml",
        )

        self.assertEqual(findings, [])

    def test_tool_confidence_tracks_untrusted_input_not_primitive_presence(self):
        safe_findings = MCPToolSecurityAnalyst().analyze(
            "response = requests.get('https://api.github.com/status', timeout=10)\n",
            "client.py",
        )
        unsafe_findings = MCPToolSecurityAnalyst().analyze(
            "def run(user_input):\n    return eval(user_input)\n",
            "app.py",
        )

        self.assertTrue(safe_findings)
        self.assertLess(safe_findings[0]["confidence_score"], 65)
        self.assertGreaterEqual(unsafe_findings[0]["confidence_score"], 65)

    def test_llm_logging_rule_reports_the_actual_line_only(self):
        code = (
            "logging.info('wrote output file')\n"
            "logging.info('prompt=%s', prompt)\n"
        )

        findings = SensitiveDataLeakageScanner().analyze(code, "app.py")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line_number"], 2)

    def test_repository_level_rules_report_the_matched_line(self):
        cases = [
            (
                PromptInjectionHunter(),
                "header = 1\nprompt = f'Answer {user_input}'\n",
                "Unsanitized User Input in Prompt",
                2,
            ),
            (
                RAGSecurityAuditor(),
                "header = 1\ndb = Chroma()\n",
                "Missing Namespace Isolation in ChromaDB",
                2,
            ),
            (
                RAGSecurityAuditor(),
                "header = 1\nvalue = 2\ndocs = load_documents(source)\n",
                "Document Ingestion Without Validation",
                3,
            ),
            (
                AgentOrchestrationSecurity(),
                "header = 1\nvalue = 2\ngoal = user_input\n",
                "Agent Goals/Tasks Set Without Validation",
                3,
            ),
            (
                ModelDataPoisoningDetector(),
                "header = 1\nvalue = 2\ndata = load_dataset(name)\n",
                "Dataset Loaded Without Validation",
                3,
            ),
        ]
        for agent, code, title, expected_line in cases:
            with self.subTest(title=title):
                findings = agent.analyze(code, "app.py")
                finding = next(item for item in findings if item["title"] == title)
                self.assertEqual(finding["line_number"], expected_line)

    def test_scan_repository_writes_real_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "app.py").write_text(
                "def run(user_input):\n    return eval(user_input)\n",
                encoding="utf-8",
            )

            result = scan_repository(target, output_root=root)

            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.scan_errors, 0)
            self.assertGreaterEqual(result.raw_findings, 1)
            self.assertTrue(result.validated_findings)
            self.assertTrue(result.markdown_report.exists())
            self.assertTrue(result.json_report.exists())
            report = json.loads(result.json_report.read_text(encoding="utf-8"))
            self.assertEqual(report["scan_metadata"]["engine_version"], "6.1.1")
            self.assertGreaterEqual(report["gauntlet_summary"]["validated_findings_count"], 1)

    def test_scan_keeps_config_and_misleading_production_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            samples = {
                "config.yaml": "command: eval(user_input)\n",
                "src/contest_utils.py": "def run(user_input):\n    return eval(user_input)\n",
                "src/latest_model.py": "def run(user_input):\n    return os.system(user_input)\n",
                "tests/app.py": "def run(user_input):\n    return eval(user_input)\n",
                "docs/app.py": "def run(user_input):\n    return eval(user_input)\n",
            }
            for name, content in samples.items():
                source = target / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(content, encoding="utf-8")

            result = scan_repository(target, output_root=root)
            validated_paths = {finding["file_path"] for finding in result.validated_findings}

            self.assertIn("config.yaml", validated_paths)
            self.assertIn("src/contest_utils.py", validated_paths)
            self.assertIn("src/latest_model.py", validated_paths)
            self.assertNotIn("tests/app.py", validated_paths)
            self.assertNotIn("docs/app.py", validated_paths)

    def test_profiler_skips_generated_files_and_reads_dotenv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = root / "node_modules"
            generated.mkdir()
            (generated / "dependency.js").write_text("langchain\n", encoding="utf-8")
            (root / ".env").write_text(
                "API_KEY=abcdefghijklmnopqrstuvwx\n",
                encoding="utf-8",
            )

            profile = TargetProfiler().profile_repository(root)

            self.assertNotIn("LangChain", profile.ai_frameworks)
            self.assertEqual(profile.secrets_found, ["API Key in .env"])

    def test_gauntlet_preserves_distinct_findings_on_the_same_line(self):
        findings = [
            {
                "category": "Example",
                "title": title,
                "file_path": "app.py",
                "line_number": 1,
                "confidence_score": 90,
            }
            for title in ("First issue", "Second issue")
        ]

        result = VerificationGauntlet().verify(findings)

        self.assertEqual(len(result["validated_findings"]), 2)

    def test_discovery_reports_its_optional_dependency(self):
        with patch.object(v6_ai_infra_security, "aiohttp", None):
            with self.assertRaisesRegex(RuntimeError, "requires aiohttp"):
                asyncio.run(InternetDiscoveryEngine().__aenter__())

    def test_dynamic_sandbox_executes_the_requested_snippet_with_hardening(self):
        docker_info = subprocess.CompletedProcess(["docker", "info"], 0)
        execution = subprocess.CompletedProcess(
            ["docker", "run"],
            0,
            stdout="ASL_V6_SANDBOX_EXPLOIT_SUCCESS\nuid=65534(nobody)",
            stderr="",
        )
        with patch("v6_dynamic_sandbox.subprocess.run", side_effect=[docker_info, execution]) as run:
            engine = V6DynamicSandboxEngine()
            result = engine.test_snippet_in_sandbox("print('custom snippet')", "Unit test")

        command = run.call_args_list[1].args[0]
        self.assertEqual(command[-1], "print('custom snippet')")
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertTrue(result["verified_exploitable"])
        self.assertEqual(result["vulnerability_type"], "Unit test")

    def test_dynamic_sandbox_requires_explicit_proof_marker(self):
        docker_info = subprocess.CompletedProcess(["docker", "info"], 0)
        execution = subprocess.CompletedProcess(
            ["docker", "run"],
            0,
            stdout="uid=65534(nobody)",
            stderr="",
        )
        with patch("v6_dynamic_sandbox.subprocess.run", side_effect=[docker_info, execution]):
            result = V6DynamicSandboxEngine().test_snippet_in_sandbox("print('uid=')")

        self.assertFalse(result["verified_exploitable"])

    def test_dynamic_sandbox_rejects_invalid_configuration(self):
        for timeout in (0, -1, True, 1.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                V6DynamicSandboxEngine(timeout_seconds=timeout)
        with self.assertRaises(ValueError):
            V6DynamicSandboxEngine(default_image="  ")

    def test_remediation_context_is_confined_to_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "target"
            root.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("SECRET_OUTSIDE_CONTEXT\n", encoding="utf-8")
            finding = {
                "title": "Example",
                "category": "Example",
                "code_evidence": "SAFE_EVIDENCE",
                "file_path": "../outside.py",
                "line_number": 1,
            }
            engine = v6_ai_infra_security.LLMSecurityReasoningEngine(provider="offline")
            with patch.object(
                engine,
                "_synthesize_reasoning",
                return_value=("thinking", "patch", "scenario"),
            ) as synthesize:
                engine.reason_and_remediate(finding, root)

        self.assertEqual(synthesize.call_args.args[2], "SAFE_EVIDENCE")

    def test_offline_remediation_never_selects_nvidia(self):
        with patch.dict("os.environ", {"NVIDIA_API_KEY": "nvapi-example"}, clear=True):
            engine = v6_ai_infra_security.LLMSecurityReasoningEngine(provider="offline")

        self.assertFalse(engine._uses_nvidia())

    def test_cli_reports_output_directory_errors_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            output_file = root / "not-a-directory"
            output_file.write_text("occupied", encoding="utf-8")

            with self.assertRaises(SystemExit) as raised:
                main([str(target), "--output-root", str(output_file)])

            self.assertEqual(raised.exception.code, 2)

    def test_fail_threshold(self):
        cases = [
            ("Critical", "high", True),
            ("High", "high", True),
            ("Medium", "high", False),
            ("Low", "none", False),
        ]
        for severity, threshold, expected in cases:
            with self.subTest(severity=severity, threshold=threshold):
                self.assertIs(
                    _threshold_reached([{"severity": severity}], threshold),
                    expected,
                )

    def test_community_scanner_does_not_require_a_key(self):
        with patch.dict("os.environ", {}, clear=True):
            status = SubscriptionManager().status

        self.assertIs(status.tier, SubscriptionTier.COMMUNITY)
        self.assertTrue(status.features["ten_specialist_scanners"])
        self.assertFalse(status.pro_key_configured)

    def test_unverified_key_does_not_unlock_pro(self):
        status = SubscriptionManager(pro_key="unverified-key").status

        self.assertIs(status.tier, SubscriptionTier.COMMUNITY)
        self.assertTrue(status.pro_key_configured)
        self.assertFalse(status.entitlement_verified)


if __name__ == "__main__":
    unittest.main()
