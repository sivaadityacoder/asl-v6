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
