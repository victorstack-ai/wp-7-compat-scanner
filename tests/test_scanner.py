import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scanner.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sample-plugin"


class ScannerCliTests(unittest.TestCase):
    def test_json_output_contains_deprecated_hook_and_fatal_risk_findings(self):
        result = subprocess.run(
            [sys.executable, str(SCANNER), str(FIXTURES), "--format", "json", "--fail-on", "low"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertGreaterEqual(data["summary"]["total"], 3)
        categories = {item["category"] for item in data["findings"]}
        self.assertIn("deprecated-hook", categories)
        self.assertIn("fatal-risk", categories)

    def test_exit_code_respects_fail_on_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plugin.php"
            path.write_text(
                "<?php\ncreate_function('$v', 'return $v;');\n",
                encoding="utf-8",
            )

            result_high = subprocess.run(
                [sys.executable, str(SCANNER), tmp, "--fail-on", "high"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result_high.returncode, 1)

            result_low = subprocess.run(
                [sys.executable, str(SCANNER), tmp, "--fail-on", "low"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result_low.returncode, 1)

    def test_clean_project_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plugin.php"
            path.write_text(
                "<?php\nadd_action('init', function () { return true; });\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCANNER), tmp, "--fail-on", "high"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("No compatibility findings", result.stdout)


if __name__ == "__main__":
    unittest.main()
