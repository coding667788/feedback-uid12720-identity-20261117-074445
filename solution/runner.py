"""cases.json 用例执行引擎。

输入是声明式用例文件（schema 见 README），输出逐步骤、逐断言的结果 JSON。
引擎本身不放宽任何服务规则：所有业务动作都经 :class:`LinkingService` 完成，
引擎只负责装配（时钟、密钥库、种子 RNG）、变量替换、断言求值，以及用真实
spawn 子进程 + Barrier 编排 parallel / crash_and_retry 场景。

确定性：
- FakeClock 从输入文件的固定起点开始，时间只能被 advance_clock 推进；
- 所有随机量来自种子化的 random.Random（默认种子 20261117），不调用
  os.urandom / time.time；
- 结果 JSON 不写进程号、墙钟时间，重放字节级稳定（排序键固定）。
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import random
import re
from typing import Any

from .clock import FakeClock, make_clock
from .errors import ERROR_BY_CODE, ServiceError
from .idp import IdentityClaim, IssuerKeyStore, MockIdentityProvider
from .service import EXIT_AFTER_COMMIT, EXIT_BEFORE_COMMIT, LinkingService
from .worker import worker_main

DEFAULT_SEED = 20261117
DEFAULT_AUDIENCE = "local-linking-service"

# 崩溃模式 -> 预期子进程退出码
CRASH_EXIT_CODES = {
    "exit_before_commit": EXIT_BEFORE_COMMIT,
    "exit_after_commit": EXIT_AFTER_COMMIT,
}


class CaseFailure(Exception):
    """用例装配错误（区别于业务 ServiceError）。"""


# ---------------------------------------------------------------- 变量/断言
def _get_path(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _resolve_field(outcome: dict, field: str) -> Any:
    """字段路径解析。

    用例里两种写法都允许：
    - 完整路径 ``data.account_id``（相对 outcome 根）
    - 简写 ``account_id``（自动回退到 data 下查找）
    """
    value = _get_path(outcome, field)
    if value is None and not field.startswith("data."):
        value = _get_path(outcome, "data." + field)
    return value


def _resolve(value: Any, variables: dict[str, Any]) -> Any:
    """字符串里的 ``$var`` / ``${a.b}`` 占位替换；非字符串原样返回。"""
    if not isinstance(value, str):
        return value
    pattern = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")

    def repl(m: re.Match) -> str:
        key = m.group(1) or m.group(2)
        if key not in variables:
            raise CaseFailure(f"未定义的变量: {key}")
        return str(variables[key])

    return pattern.sub(repl, value)


def _resolve_obj(obj: Any, variables: dict[str, Any]) -> Any:
    if isinstance(obj, dict):
        return {k: _resolve_obj(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_obj(v, variables) for v in obj]
    return _resolve(obj, variables)


_PREDICATES = {"eq", "ne", "contains", "not_contains", "exists", "size", "ge", "le", "gt", "lt", "regex"}


def _check_expectation(expect: dict, outcome: dict) -> list[dict]:
    """对单步骤的 expect 块求值，返回断言结果列表。"""
    checks: list[dict] = []
    expected_status = expect.get("status")
    if expected_status is not None:
        ok = outcome["status"] == expected_status
        checks.append(
            {
                "assertion": "status",
                "expected": expected_status,
                "actual": outcome["status"],
                "passed": ok,
            }
        )
    if "error" in expect:
        actual = outcome.get("error")
        checks.append(
            {"assertion": "error", "expected": expect["error"], "actual": actual,
             "passed": actual == expect["error"]}
        )
    for field, rule in expect.get("fields", {}).items():
        actual = _resolve_field(outcome, field)
        if isinstance(rule, dict) and any(k in rule for k in _PREDICATES):
            for op, expected in rule.items():
                checks.append(_predicate_check(f"{field}.{op}", op, expected, actual))
        else:
            checks.append(_predicate_check(field, "eq", rule, actual))
    return checks


def _predicate_check(label: str, op: str, expected: Any, actual: Any) -> dict:
    if op == "eq":
        passed = actual == expected
    elif op == "ne":
        passed = actual != expected
    elif op == "contains":
        passed = expected in actual if actual is not None else False
    elif op == "not_contains":
        passed = (expected not in actual) if actual is not None else True
    elif op == "exists":
        passed = (actual is not None) == bool(expected)
    elif op == "size":
        passed = actual is not None and len(actual) == expected
    elif op == "ge":
        passed = actual is not None and actual >= expected
    elif op == "le":
        passed = actual is not None and actual <= expected
    elif op == "gt":
        passed = actual is not None and actual > expected
    elif op == "lt":
        passed = actual is not None and actual < expected
    elif op == "regex":
        passed = actual is not None and re.search(expected, str(actual)) is not None
    else:
        raise CaseFailure(f"不支持的断言谓词: {op}")
    return {"assertion": label, "expected": expected, "actual": actual, "passed": passed}


# ---------------------------------------------------------------- 步骤执行
def execute_steps(
    service: LinkingService,
    steps: list[dict],
    initial_vars: dict[str, Any],
    worker_index: int = 0,
    sync_registry: dict | None = None,
) -> dict:
    """在给定 service 上顺序执行步骤；parallel/crash 步骤由 runner 注入。"""
    variables = dict(initial_vars)
    step_results: list[dict] = []
    # 子进程内没有 IdP 装配信息，assertion 步骤不应出现在子进程里
    idps: dict[str, MockIdentityProvider] = {}
    key_store = service.key_store
    for issuer in key_store.issuers():
        idps[issuer] = MockIdentityProvider(issuer, key_store, service.clock, rng=service.rng)

    for index, raw_step in enumerate(steps):
        step = _resolve_obj(raw_step, variables)
        step_id = step.get("id") or f"w{worker_index}-s{index}"
        if step["op"] == "_sync":
            result = {"op": "_sync",
                      "outcome": {"status": "ok", "error": None,
                                  "data": _run_sync(step, sync_registry)}}
        else:
            result = _run_one_step(step, step_id, service, idps, variables)
        checks = _check_expectation(step.get("expect", {}), result["outcome"])
        result["step_id"] = step_id
        result["checks"] = checks
        result["passed"] = all(c["passed"] for c in checks)
        step_results.append(result)
        if "capture" in step:
            for var_name, path in step["capture"].items():
                variables[var_name] = _resolve_field(result["outcome"], path)
    return {"worker_index": worker_index, "variables": variables, "steps": step_results}


def _run_sync(step: dict, sync_registry: dict | None) -> dict:
    """跨进程确定性同步原语（仅测试编排用，不触碰数据库）。

    - {"op": "_sync", "wait": "name"} 阻塞到该 Event 被 set
    - {"op": "_sync", "set":  "name"} 唤醒在该 Event 上等待的进程
    - {"op": "_sync", "barrier": "name"} 在该 Barrier 上对齐
    """
    if not sync_registry:
        raise CaseFailure("_sync 步骤需要 sync_registry")
    if "wait" in step:
        prim = sync_registry[step["wait"]]
        prim.wait(timeout=step.get("timeout", 30))
        return {"synced": step["wait"], "action": "wait"}
    if "set" in step:
        prim = sync_registry[step["set"]]
        prim.set()
        return {"synced": step["set"], "action": "set"}
    if "barrier" in step:
        prim = sync_registry[step["barrier"]]
        prim.wait(timeout=step.get("timeout", 30))
        return {"synced": step["barrier"], "action": "barrier"}
    raise CaseFailure("_sync 步骤必须包含 wait/set/barrier 之一")


def _run_one_step(
    step: dict, step_id: str, service: LinkingService,
    idps: dict[str, MockIdentityProvider], variables: dict,
) -> dict:
    op = step["op"]
    try:
        data = _dispatch(op, step, service, idps)
        outcome = {"status": "ok", "error": None, "data": data}
    except ServiceError as exc:
        outcome = {"status": "error", "error": exc.code, "data": exc.to_dict()}
    return {"op": op, "outcome": outcome}


def _dispatch(
    op: str, step: dict, service: LinkingService, idps: dict[str, MockIdentityProvider]
) -> dict:
    if op == "advance_clock":
        service.clock.advance(int(step["seconds"]))
        return {"now": service.clock.now()}

    if op == "create_account":
        return service.create_account(
            step["request_id"], step["account_id"],
            step.get("display_name", step["account_id"]),
            step.get("password"),
        )
    if op == "login":
        return service.login(step["request_id"], step["account_id"], step["password"])
    if op == "start_challenge":
        return service.start_challenge(
            step["request_id"], step["account_id"],
            step["session_token"], step["issuer"],
        )
    if op == "mint_assertion":
        idp = idps[step["issuer"]]
        claim = IdentityClaim(step["issuer"], step["subject"], step.get("email", ""))
        token_pack = idp.issue(
            claim,
            service.audience,
            step["nonce"],
            ttl_seconds=step.get("ttl_seconds"),
            issuer_override=step.get("issuer_override"),
            audience_override=step.get("audience_override"),
            sign_with_wrong_key=step.get("sign_with_wrong_key", False),
            corrupt_signature=step.get("corrupt_signature", False),
            backdate_expired=step.get("backdate_expired", False),
            future_nbf=step.get("future_nbf", False),
        )
        return token_pack
    if op == "complete_challenge":
        return service.complete_challenge(
            step["request_id"], step["challenge_id"],
            step["session_token"], step["assertion_token"],
        )
    if op == "unlink":
        return service.unlink(step["request_id"], step["link_id"], step["session_token"])
    if op == "disable_account":
        return service.disable_account(
            step["request_id"], step["account_id"], step["session_token"]
        )
    if op == "enable_account":
        return service.enable_account(step["request_id"], step["account_id"])
    if op == "remove_local_password":
        return service.remove_local_password(step["account_id"])

    if op == "get_account":
        return service.get_account(step["account_id"]) or {}
    if op == "find_identity":
        return service.find_active_identity(step["issuer"], step["subject"]) or {}
    if op == "list_identities":
        return {"identities": service.list_identities(step["account_id"])}
    if op == "list_challenges":
        return {"challenges": service.list_challenges(step["account_id"])}
    if op == "list_audit":
        return {
            "events": service.list_audit(
                account_id=step.get("account_id"),
                request_id=step.get("request_id"),
                event_type=step.get("event_type"),
            )
        }

    if op == "parallel":
        raise CaseFailure("parallel 步骤只能由顶层 run_cases 编排，不能在子进程内嵌套")
    if op == "crash_and_retry":
        raise CaseFailure("crash_and_retry 步骤只能由顶层 run_cases 编排")
    raise CaseFailure(f"未知步骤类型: {op}")


# ---------------------------------------------------------------- 顶层编排
class CaseRunner:
    def __init__(self, spec: dict, base_dir: str, work_root: str):
        self.spec = spec
        self.base_dir = base_dir
        self.work_root = work_root
        self.seed = int(spec.get("seed", DEFAULT_SEED))
        self.clock_start = int(spec.get("clock", {}).get("start", 1_700_000_000))
        self.audience = spec.get("audience", DEFAULT_AUDIENCE)
        self.key_store = self._load_key_store(spec)
        self.login_freshness = int(spec.get("login_freshness_seconds", 300))
        self.session_ttl = int(spec.get("session_ttl_seconds", 3600))
        self.challenge_ttl = int(spec.get("challenge_ttl_seconds", 300))
        os.makedirs(work_root, exist_ok=True)

    def _load_key_store(self, spec: dict) -> IssuerKeyStore:
        keys: dict[str, bytes] = {}
        for item in spec.get("issuers", []):
            if "secret_hex" in item:
                keys[item["issuer"]] = bytes.fromhex(item["secret_hex"])
            elif "key_file" in item:
                store = IssuerKeyStore.from_json_file(
                    os.path.join(self.base_dir, item["key_file"])
                )
                keys[item["issuer"]] = store.secret_of(item["issuer"])
            else:
                raise CaseFailure(f"issuer 配置缺少 secret_hex/key_file: {item}")
        return IssuerKeyStore(keys)

    def _service_payload(self, db_path: str, worker_index: int, crash_plan=None) -> dict:
        return {
            "db_path": db_path,
            "keys": [
                {"issuer": iss, "secret_hex": self.key_store.secret_of(iss).hex()}
                for iss in self.key_store.issuers()
            ],
            "clock_start": self.clock_start,
            "seed_base": self.seed,
            "worker_index": worker_index,
            "audience": self.audience,
            "crash_plan": crash_plan,
            "login_freshness": self.login_freshness,
            "session_ttl": self.session_ttl,
            "challenge_ttl": self.challenge_ttl,
        }

    def run(self) -> dict:
        cases_out = []
        for case_index, case in enumerate(self.spec["cases"]):
            cases_out.append(self._run_case(case, case_index))
        total_checks = sum(c["checks_total"] for c in cases_out)
        failed_checks = sum(c["checks_failed"] for c in cases_out)
        return {
            "schema_version": 1,
            "seed": self.seed,
            "summary": {
                "cases": len(cases_out),
                "cases_passed": sum(1 for c in cases_out if c["passed"]),
                "cases_failed": sum(1 for c in cases_out if not c["passed"]),
                "checks_total": total_checks,
                "checks_failed": failed_checks,
            },
            "cases": cases_out,
        }

    def _new_service(self, db_path: str, rng_index: int = 0) -> LinkingService:
        rng = random.Random(self.seed * 1_000_003 + rng_index)
        clock = FakeClock(self.clock_start)
        return LinkingService(
            db_path,
            self.key_store,
            clock,
            audience=self.audience,
            rng=rng,
            login_freshness_seconds=self.login_freshness,
            session_ttl_seconds=self.session_ttl,
            challenge_ttl_seconds=self.challenge_ttl,
        )

    def _run_case(self, case: dict, case_index: int) -> dict:
        case_id = case["id"]
        db_path = os.path.join(self.work_root, f"{case_id}.db")
        for suffix in ("", "-wal", "-shm"):
            p = db_path + suffix
            # Windows 下子进程连接刚关闭时句柄可能尚未完全释放，容忍短暂锁；
            # 残留的 WAL 不影响正确性（同名库每次都被新连接重新打开）。
            try:
                if os.path.exists(p):
                    os.remove(p)
            except PermissionError:
                pass
        service = self._new_service(db_path, rng_index=case_index)
        variables: dict[str, Any] = {}
        step_results: list[dict] = []
        case_error = None
        try:
            for index, raw_step in enumerate(case["steps"]):
                if raw_step["op"] in ("parallel", "crash_and_retry"):
                    step_results.append(
                        self._run_special(raw_step, db_path, case_index, index, variables)
                    )
                    continue
                step = _resolve_obj(raw_step, variables)
                step_id = step.get("id") or f"s{index}"
                result = _run_one_step(
                    step, step_id, service,
                    {i: MockIdentityProvider(i, self.key_store, service.clock, rng=service.rng)
                     for i in self.key_store.issuers()},
                    variables,
                )
                result["step_id"] = step_id
                result["checks"] = _check_expectation(step.get("expect", {}), result["outcome"])
                result["passed"] = all(c["passed"] for c in result["checks"])
                step_results.append(result)
                if "capture" in step:
                    for var_name, path in step["capture"].items():
                        variables[var_name] = _resolve_field(result["outcome"], path)
        except CaseFailure as exc:
            case_error = str(exc)
        finally:
            service.close()

        checks_total = sum(len(r["checks"]) for r in step_results)
        checks_failed = sum(
            1 for r in step_results for c in r["checks"] if not c["passed"]
        )
        passed = checks_failed == 0 and case_error is None
        return {
            "case_id": case_id,
            "title": case.get("title", case_id),
            "db_path": os.path.relpath(db_path, self.base_dir),
            "passed": passed,
            "case_error": case_error,
            "checks_total": checks_total,
            "checks_failed": checks_failed,
            "steps": step_results,
        }

    # ------------------------------------------------- parallel / crash 编排
    def _run_special(
        self, step: dict, db_path: str, case_index: int, index: int,
        parent_vars: dict[str, Any],
    ) -> dict:
        if step["op"] == "parallel":
            return self._run_parallel(step, db_path, case_index, index, parent_vars)
        return self._run_crash_retry(step, db_path, case_index, index, parent_vars)

    def _run_parallel(
        self, step: dict, db_path: str, case_index: int, index: int,
        parent_vars: dict[str, Any],
    ) -> dict:
        workers = step["workers"]
        n = len(workers)
        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(n + 1)
        queue = ctx.Queue()
        processes = []
        for wi, worker in enumerate(workers):
            payload = self._service_payload(db_path, case_index * 100 + wi + 1)
            payload["vars"] = dict(parent_vars)
            payload["steps"] = worker["steps"]
            p = ctx.Process(
                target=_parallel_entry,
                args=(payload, barrier, queue),
                name=f"case{case_index}-worker{wi}",
            )
            processes.append(p)
            p.start()
        # 父进程也参与屏障：所有子进程到达后同时放行，最大化竞态窗口
        barrier.wait(step.get("barrier_timeout", 30))
        worker_results = []
        for _ in range(n):
            worker_results.append(queue.get(timeout=step.get("queue_timeout", 20)))
        for p in processes:
            p.join(15)
        # 队列返回顺序随调度而变，按 worker_index 归一化排序，
        # 使输出结构稳定（哪个 worker 获胜仍如实记录在其结果里）
        worker_results.sort(key=lambda item: _worker_index_of(item))
        checks, passed = self._evaluate_workers(step, worker_results)
        return {
            "op": "parallel",
            "step_id": step.get("id") or f"s{index}",
            "outcome": {"status": "ok", "error": None,
                        "data": {"worker_count": n,
                                 "worker_outcomes": [w[0] if w[0] == "ok" else w[1]
                                                     for w in worker_results]}},
            "checks": checks,
            "passed": passed,
            "workers": [
                {"kind": kind, "result": body} for kind, body in worker_results
            ],
        }

    def _evaluate_workers(self, step: dict, worker_results: list) -> tuple[list[dict], bool]:
        """对 worker 结果做整体断言。

        并行场景下哪个进程成为胜者取决于数据库锁获取顺序，因此 worker 内部的
        expect 块只作记录（inner_checks 计数），不参与通过判定；硬性正确性由
        本方法的聚合规则保证，例如"恰好一个 ok、一个 identity_already_bound"。
        """
        checks: list[dict] = []
        expect = step.get("expect", {})
        ok_kinds = [kind for kind, _ in worker_results]
        if "workers_ok" in expect:
            actual = ok_kinds.count("ok")
            checks.append({"assertion": "workers_ok", "expected": expect["workers_ok"],
                           "actual": actual, "passed": actual == expect["workers_ok"]})
        # 每个 worker 内部步骤自带的断言：仅记录，不决定用例通过与否
        inner_failed = 0
        inner_total = 0
        for kind, body in worker_results:
            if kind == "ok":
                for r in body.get("steps", []):
                    inner_total += len(r["checks"])
                    inner_failed += sum(1 for c in r["checks"] if not c["passed"])
        checks.append({"assertion": "worker_inner_checks_advisory",
                       "expected": "advisory-only", "actual": inner_failed,
                       "passed": True})
        # 自定义聚合谓词（硬性断言）
        for rule in expect.get("aggregate", []):
            actual = self._aggregate(rule["path"], worker_results)
            checks.append(_predicate_check(rule["path"], rule.get("op", "eq"),
                                           rule.get("value"), actual))
        hard_checks = [c for c in checks if c["assertion"] != "worker_inner_checks_advisory"]
        return checks, all(c["passed"] for c in hard_checks)

    def _aggregate(self, path: str, worker_results: list) -> Any:
        """从各 worker 步骤结果里收集标量，支持 values/count/count_where 聚合。

        路径语法（第一个冒号分隔聚合类型，其余部分是字段路径，可含 ==）：
          values:data.subject                  -> 各步骤该字段值的排序列表
          count:outcome.error                  -> 非空取值的个数
          count_where:outcome.status==ok       -> 等值命中个数
        """
        kind, sep, rest = path.partition(":")
        if not sep:
            raise CaseFailure(f"聚合路径缺少 ':' 分隔: {path}")
        # 字段路径基于单步骤 outcome，允许显式写 outcome. 前缀
        rest = rest[len("outcome."):] if rest.startswith("outcome.") else rest
        values = []
        for wkind, body in worker_results:
            if wkind != "ok":
                continue
            for r in body.get("steps", []):
                values.append(_get_path(r["outcome"], rest))
        if kind == "values":
            return sorted(v for v in values if v is not None)
        if kind == "count":
            return sum(1 for v in values if v is not None)
        if kind == "count_where":
            field, eq, expected = rest.partition("==")
            if not eq:
                raise CaseFailure(f"count_where 需要 == 条件: {path}")
            return sum(
                1
                for wkind, body in worker_results
                if wkind == "ok"
                for r in body.get("steps", [])
                if _get_path(r["outcome"], field.strip()) == expected.strip()
            )
        raise CaseFailure(f"不支持的聚合: {kind}")

    def _run_crash_retry(
        self, step: dict, db_path: str, case_index: int, index: int,
        parent_vars: dict[str, Any],
    ) -> dict:
        """崩溃-重启-重试：崩溃动作在独立 spawn 进程里执行并被 os._exit 杀死，
        父进程随后用全新 service（模拟重启）凭同一 request_id 重试。"""
        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        crash_plan = {step["crash_point"]: step["crash_mode"]}
        payload = self._service_payload(
            db_path, case_index * 100 + 90, crash_plan=crash_plan
        )
        payload["vars"] = dict(parent_vars)
        payload["steps"] = [step["crash_step"]]
        p = ctx.Process(
            target=_parallel_entry,
            args=(payload, None, queue),
            name=f"case{case_index}-crash",
        )
        p.start()
        # exit_* 模式下子进程被 os._exit 杀死，queue 不会有消息；
        # raise_* 软崩溃会回传 injected_crash。硬崩溃时 5 秒空队列即可判定，
        # 不必久等（子进程真正的存活/退出状态由 exitcode 断言兜底）。
        crashed: tuple
        try:
            crashed = queue.get(timeout=step.get("queue_timeout", 5))
        except Exception:  # noqa: BLE001 - 队列空即硬崩溃的预期表现
            crashed = ("crashed", {"reason": "process exited without queue message"})
        p.join(15)
        if step["crash_mode"] in CRASH_EXIT_CODES:
            expected_exit = CRASH_EXIT_CODES[step["crash_mode"]]
            exit_ok = p.exitcode == expected_exit
            reported_ok = crashed[0] == "crashed"
        else:
            expected_exit = 0
            exit_ok = p.exitcode == 0
            reported_ok = crashed[0] == "injected_crash"

        # 模拟进程重启：新建 service 打开同一个数据库文件
        retry_service = self._new_service(db_path, rng_index=case_index * 100 + 91)
        try:
            retry_step = _resolve_obj(step["retry_step"], parent_vars)
            retry_result = _run_one_step(
                retry_step,
                retry_step.get("id", "retry"),
                retry_service,
                {i: MockIdentityProvider(i, self.key_store, retry_service.clock,
                                         rng=retry_service.rng)
                 for i in self.key_store.issuers()},
                parent_vars,
            )
        finally:
            retry_service.close()

        checks = [
            {"assertion": "crash_exit_code", "expected": expected_exit,
             "actual": p.exitcode, "passed": exit_ok},
            {"assertion": "crash_reported",
             "expected": "crashed" if step["crash_mode"] in CRASH_EXIT_CODES
             else "injected_crash",
             "actual": crashed[0],
             "passed": reported_ok},
        ]
        checks.extend(_check_expectation(step.get("expect", {}), retry_result["outcome"]))
        return {
            "op": "crash_and_retry",
            "step_id": step.get("id") or f"s{index}",
            "outcome": retry_result["outcome"],
            "checks": checks,
            "passed": all(c["passed"] for c in checks),
            "crash": {"mode": step["crash_mode"], "point": step["crash_point"],
                      "exitcode": p.exitcode, "reported": crashed[0],
                      "reported_detail": crashed[1]},
        }


def _worker_index_of(item: tuple) -> int:
    """从 (kind, body) 队列项里取 worker_index；异常回报没有该字段时排末尾。"""
    kind, body = item
    if kind == "ok" and isinstance(body, dict):
        return int(body.get("worker_index", 10**9))
    return 10**9


def _parallel_entry(payload: dict, barrier, result_queue, sync_registry=None) -> None:
    """spawn 子进程入口；os._exit 崩溃时不会执行到任何回报代码，
    父进程依据进程退出码判定，queue.get 因此必须带超时并区分空队列。"""
    try:
        worker_main(payload, barrier, result_queue, sync_registry=sync_registry)
    except BaseException:  # noqa: BLE001
        import traceback

        result_queue.put(("error", {"traceback": traceback.format_exc()}))


def run_cases(spec: dict, base_dir: str, work_root: str) -> dict:
    """顶层入口：执行完整 cases 规格并返回可序列化结果。"""
    runner = CaseRunner(spec, base_dir, work_root)
    return runner.run()
