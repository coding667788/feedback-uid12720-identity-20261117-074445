"""端到端测试：直接驱动项目根目录的 cases.json 声明式规格。

这是 `python -m solution --input cases.json --output ...` 的库内等价物，
覆盖全部 13 个用例（含真实 spawn 双进程 + Barrier 的抢绑、双解绑、崩溃重启），
断言：
- 所有用例与所有断言通过；
- 关键并发用例的聚合不变量（恰一个胜者、败者错误码正确）；
- 结果结构符合输出 schema；
- 重复执行的判定层稳定（固定种子可重放）。
"""

from __future__ import annotations

import json
import os
import shutil
import unittest

from solution.runner import run_cases

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CASES = os.path.join(_ROOT, "cases.json")


class EndToEndCasesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_root = os.path.join(_ROOT, ".runtime-tmp", "e2e-run")
        shutil.rmtree(cls.work_root, ignore_errors=True)
        with open(_CASES, encoding="utf-8") as fh:
            cls.spec = json.load(fh)
        cls.result = run_cases(cls.spec, _ROOT, cls.work_root)

    def test_summary_all_passed(self):
        summary = self.result["summary"]
        self.assertEqual(summary["cases_failed"], 0)
        self.assertEqual(summary["checks_failed"], 0)
        self.assertEqual(summary["cases_passed"], summary["cases"])
        self.assertGreater(summary["checks_total"], 100)

    def test_every_case_passed_and_recorded(self):
        case_ids = [c["case_id"] for c in self.result["cases"]]
        # 必测验收场景一个不缺
        for required in (
            "case01_same_email_distinct_subjects",
            "case02_browser_session_swap",
            "case03_concurrent_race_binding",
            "case04b_concurrent_double_unlink",
            "case07_crash_before_commit_then_retry",
            "case08_crash_after_commit_then_retry",
            "case09_disable_linearization_and_revocation",
        ):
            self.assertIn(required, case_ids)
        for case in self.result["cases"]:
            self.assertTrue(case["passed"], f"{case['case_id']} 未通过")
            self.assertEqual(case["checks_failed"], 0)

    def test_race_case_single_winner_invariant(self):
        case = next(
            c for c in self.result["cases"]
            if c["case_id"] == "case03_concurrent_race_binding"
        )
        race = next(s for s in case["steps"] if s["op"] == "parallel")
        # 真实两个进程都正常返回
        workers_ok = next(
            chk for chk in race["checks"] if chk["assertion"] == "workers_ok"
        )
        self.assertEqual(workers_ok["actual"], 2)
        # 恰好一个 ok、一个 identity_already_bound
        aggregates = {
            chk["assertion"]: chk for chk in race["checks"]
            if chk["assertion"].startswith(("count",))
        }
        ok_rule = aggregates["count_where:outcome.status==ok"]
        bound_rule = aggregates["count_where:outcome.error==identity_already_bound"]
        self.assertTrue(ok_rule["passed"])
        self.assertEqual(ok_rule["actual"], 1)
        self.assertTrue(bound_rule["passed"])
        self.assertEqual(bound_rule["actual"], 1)

    def test_output_schema_shape(self):
        self.assertEqual(self.result["schema_version"], 1)
        self.assertIn("seed", self.result)
        for case in self.result["cases"]:
            for key in ("case_id", "title", "passed", "checks_total",
                        "checks_failed", "steps"):
                self.assertIn(key, case)
            for step in case["steps"]:
                self.assertIn("outcome", step)
                self.assertIn(step["outcome"]["status"], ("ok", "error"))

    def test_replay_verdict_is_stable(self):
        second = run_cases(self.spec, _ROOT,
                           os.path.join(_ROOT, ".runtime-tmp", "e2e-run-2"))
        verdict = lambda d: [  # noqa: E731
            (c["case_id"], c["passed"], c["checks_total"], c["checks_failed"])
            for c in d["cases"]
        ]
        self.assertEqual(verdict(self.result), verdict(second))
        self.assertEqual(self.result["summary"], second["summary"])


if __name__ == "__main__":
    unittest.main()
