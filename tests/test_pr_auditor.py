import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ACTION_MODULE_PATH = Path(__file__).resolve().parents[1] / "asl-v6-action" / "pr_auditor.py"
ACTION_SPEC = importlib.util.spec_from_file_location("asl_v6_pr_auditor", ACTION_MODULE_PATH)
pr_auditor = importlib.util.module_from_spec(ACTION_SPEC)
sys.modules[ACTION_SPEC.name] = pr_auditor
ACTION_SPEC.loader.exec_module(pr_auditor)


class PrAuditorTests(unittest.TestCase):
    def test_get_pr_files_fetches_every_page(self):
        first_page = [{"filename": f"file-{index}.py"} for index in range(100)]
        second_page = [{"filename": "last.py"}]
        responses = []
        for payload in (first_page, second_page):
            response = Mock()
            response.json.return_value = payload
            responses.append(response)

        with patch.object(pr_auditor.requests, "get", side_effect=responses) as request:
            files = pr_auditor.get_pr_files("token", "owner/repo", 7)

        self.assertEqual(len(files), 101)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0].kwargs["params"]["page"], 1)
        self.assertEqual(request.call_args_list[1].kwargs["params"]["page"], 2)
        self.assertEqual(
            request.call_args_list[0].kwargs["timeout"],
            pr_auditor.GITHUB_API_TIMEOUT,
        )

    def test_added_lines_from_patch_tracks_only_new_lines(self):
        diff = """@@ -10,3 +10,4 @@ def example():
 context
-removed
+added
+another
 context
"""

        self.assertEqual(pr_auditor.added_lines_from_patch(diff), {11, 12})

    def test_findings_on_added_lines_excludes_preexisting_findings(self):
        findings = [
            {"file_path": "app.py", "line_number": 4, "title": "old"},
            {"file_path": "app.py", "line_number": 8, "title": "new"},
            {"file_path": "other.py", "line_number": 8, "title": "other"},
        ]

        introduced = pr_auditor.findings_on_added_lines(findings, {"app.py": {8}})

        self.assertEqual([finding["title"] for finding in introduced], ["new"])

    def test_resolve_changed_file_rejects_symlinks_and_escaped_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            workspace.mkdir()
            safe_file = workspace / "component.tsx"
            safe_file.write_text("export default null;\n", encoding="utf-8")
            outside = Path(directory) / "outside.py"
            outside.write_text("eval(user_input)\n", encoding="utf-8")
            link = workspace / "linked.py"
            link.symlink_to(outside)

            self.assertEqual(
                pr_auditor.resolve_changed_file(workspace, "component.tsx"),
                safe_file,
            )
            self.assertIsNone(pr_auditor.resolve_changed_file(workspace, "linked.py"))
            self.assertIsNone(pr_auditor.resolve_changed_file(workspace, "../outside.py"))

    def test_scanner_failure_does_not_skip_later_agents(self):
        class BrokenAgent:
            def analyze(self, content, relative_path):
                raise RuntimeError("broken scanner")

        class WorkingAgent:
            def analyze(self, content, relative_path):
                return [{"file_path": relative_path, "line_number": 1}]

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            with patch.object(
                pr_auditor,
                "ALL_SPECIALIST_AGENTS",
                [BrokenAgent, WorkingAgent],
            ):
                findings = pr_auditor.scan_file_with_agents(source, "app.py")

        self.assertEqual(findings, [{"file_path": "app.py", "line_number": 1}])

    def test_action_supports_cli_source_extensions(self):
        self.assertTrue({".jsx", ".tsx"}.issubset(pr_auditor.SUPPORTED_SUFFIXES))

    def test_pr_gate_applies_only_to_findings_on_added_lines(self):
        for finding_line, should_fail in ((1, False), (2, True)):
            with self.subTest(finding_line=finding_line), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                source = workspace / "app.py"
                source.write_text("old vulnerable line\nnew vulnerable line\n", encoding="utf-8")
                event_path = workspace / "event.json"
                event_path.write_text(
                    json.dumps(
                        {
                            "repository": {"full_name": "owner/repo"},
                            "pull_request": {
                                "number": 7,
                                "head": {"sha": "abc123"},
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                changed_files = [
                    {
                        "filename": "app.py",
                        "status": "modified",
                        "patch": "@@ -1,1 +1,2 @@\n old vulnerable line\n+new vulnerable line\n",
                    }
                ]
                finding = {
                    "file_path": "app.py",
                    "line_number": finding_line,
                    "severity": "High",
                    "title": "Example issue",
                    "category": "Example",
                }
                gauntlet_result = {
                    "validated_findings": [finding],
                    "fp_reduction_percentage": 0.0,
                }
                environment = {
                    "GITHUB_TOKEN": "token",
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_WORKSPACE": str(workspace),
                    "FAIL_ON_HIGH_SEVERITY": "true",
                }

                with (
                    patch.dict("os.environ", environment, clear=True),
                    patch.object(pr_auditor, "get_pr_files", return_value=changed_files),
                    patch.object(pr_auditor, "scan_file_with_agents", return_value=[finding]),
                    patch.object(pr_auditor, "VerificationGauntlet") as gauntlet,
                    patch.object(pr_auditor, "LLMSecurityReasoningEngine"),
                    patch.object(pr_auditor, "generate_sarif") as generate_sarif,
                    patch.object(pr_auditor, "post_pr_review") as post_review,
                ):
                    gauntlet.return_value.verify.return_value = gauntlet_result
                    if should_fail:
                        with self.assertRaises(SystemExit) as raised:
                            pr_auditor.main()
                        self.assertEqual(raised.exception.code, 1)
                        post_review.assert_called_once()
                        self.assertEqual(generate_sarif.call_args.args[0], [finding])
                    else:
                        pr_auditor.main()
                        post_review.assert_not_called()
                        self.assertEqual(generate_sarif.call_args.args[0], [])

    def test_generate_sarif_uses_valid_rule_and_line_defaults(self):
        finding = {
            "owasp_llm_id": "",
            "category": "Example rule",
            "line_number": 0,
            "file_path": "app.py",
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.sarif"

            pr_auditor.generate_sarif([finding], Path(directory), output)

            report = json.loads(output.read_text(encoding="utf-8"))
        run = report["runs"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "Example rule")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
