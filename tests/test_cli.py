"""CLI 契约测试：以真实子进程运行 `python -m solution`。

验证题目要求的入口在干净进程里可用、退出码语义正确、输出文件落盘且为合法
schema；并验证输入文件不存在时返回退出码 2。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliEntryPointTest(unittest.TestCase):
    def setUp(self):
        self.work = os.path.join(_ROOT, ".runtime-tmp", "cli-test")
        shutil.rmtree(self.work, ignore_errors=True)
        os.makedirs(self.work, exist_ok=True)
        self.output = os.path.join(self.work, "result.json")

    def _run_cli(self, input_path, output_path):
        return subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", input_path, "--output", output_path],
            cwd=_ROOT, capture_output=True, text=True, timeout=240,
        )

    def test_cli_runs_cases_and_writes_valid_output(self):
        proc = self._run_cli(os.path.join(_ROOT, "cases.json"), self.output)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(self.output))
        with open(self.output, encoding="utf-8") as fh:
            result = json.load(fh)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["summary"]["cases_failed"], 0)
        self.assertEqual(result["summary"]["checks_failed"], 0)
        self.assertIn("用例", proc.stdout)

    def test_cli_missing_input_returns_exit_code_2(self):
        proc = self._run_cli(
            os.path.join(self.work, "does-not-exist.json"), self.output
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("不存在", proc.stderr)


if __name__ == "__main__":
    unittest.main()
