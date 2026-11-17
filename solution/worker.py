"""真实子进程入口（Windows spawn 友好：只含模块级函数）。

runner 在 parallel / crash 步骤里用 ``multiprocessing.get_context("spawn")``
启动本模块的 :func:`worker_main`。每个子进程：

1. 独立打开自己的 SQLite 连接（绝不共享父进程连接/锁），
2. 从同一固定起点构造 FakeClock（可被 advance_clock 步骤推进），
3. 在 Barrier 上与其他进程对齐后再执行关键写操作，从而用 *真实操作系统
   进程 + 数据库锁* 复现竞态，而不是线程锁。

payload 经 pickle 传递，必须只含纯数据（str/dict/list/int/bool/None）。
barrier 为 None 时表示 crash 场景（无需对齐，直接跑崩溃步骤）。
"""

from __future__ import annotations

import random
import traceback

from .clock import FakeClock
from .errors import InjectedCrash
from .idp import IssuerKeyStore
from .service import LinkingService


def _build_service(payload: dict) -> LinkingService:
    key_store = IssuerKeyStore(
        {item["issuer"]: bytes.fromhex(item["secret_hex"]) for item in payload["keys"]}
    )
    clock = FakeClock(payload["clock_start"])
    seed = int(payload["seed_base"]) * 1_000_003 + int(payload["worker_index"])
    rng = random.Random(seed)
    return LinkingService(
        payload["db_path"],
        key_store,
        clock,
        audience=payload.get("audience", "local-linking-service"),
        rng=rng,
        crash_plan=payload.get("crash_plan"),
        login_freshness_seconds=payload.get("login_freshness", 300),
        session_ttl_seconds=payload.get("session_ttl", 3600),
        challenge_ttl_seconds=payload.get("challenge_ttl", 300),
    )


def worker_main(payload: dict, barrier, result_queue, sync_registry=None) -> None:
    """子进程主函数。延迟 import runner 以最小化 spawn 重导入面。

    sync_registry: 可选的 {名称: Barrier/Event} 字典，配合步骤里的
    ``{"op": "_sync", "wait"/"set": 名称}`` 实现跨进程的确定性先后编排，
    避免用 sleep 猜测调度顺序。
    """
    from .runner import execute_steps  # 避免循环导入

    service = None
    try:
        if barrier is not None:
            # 所有进程（含父进程）在此对齐，放行后同时进入事务竞争写锁
            barrier.wait()
        service = _build_service(payload)
        result = execute_steps(
            service,
            payload["steps"],
            dict(payload["vars"]),
            payload["worker_index"],
            sync_registry=sync_registry,
        )
        result_queue.put(("ok", result))
    except InjectedCrash as exc:
        # raise_before_commit 软崩溃：事务已回滚，进程存活并回报
        result_queue.put(("injected_crash", {"message": str(exc)}))
    except BaseException:  # noqa: BLE001 - 子进程必须把任何异常回传父进程
        result_queue.put(
            ("error", {"traceback": traceback.format_exc()})
        )
    finally:
        if service is not None:
            service.close()
