"""命令行入口：python -m solution --input cases.json --output result.json

退出码：
- 0  全部用例通过
- 1  存在失败断言或用例装配错误
- 2  输入文件/参数错误
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .runner import run_cases


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="本地账号关联服务用例执行器（HMAC 模拟身份源）",
    )
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="结果 JSON 输出路径")
    parser.add_argument(
        "--work-dir",
        default=None,
        help="SQLite 等运行产物目录，默认 <输入目录>/.runtime-tmp/cases-run",
    )
    args = parser.parse_args(argv)

    input_path = os.path.abspath(args.input)
    if not os.path.isfile(input_path):
        print(f"输入文件不存在: {input_path}", file=sys.stderr)
        return 2
    base_dir = os.path.dirname(input_path)
    with open(input_path, "r", encoding="utf-8") as fh:
        spec = json.load(fh)

    work_root = (
        os.path.abspath(args.work_dir)
        if args.work_dir
        else os.path.join(base_dir, ".runtime-tmp", "cases-run")
    )
    os.makedirs(work_root, exist_ok=True)

    result = run_cases(spec, base_dir, work_root)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")

    summary = result["summary"]
    print(
        f"用例 {summary['cases_passed']}/{summary['cases']} 通过，"
        f"断言 {summary['checks_total'] - summary['checks_failed']}"
        f"/{summary['checks_total']} 通过；结果已写入 {args.output}"
    )
    return 0 if summary["cases_failed"] == 0 and summary["checks_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
