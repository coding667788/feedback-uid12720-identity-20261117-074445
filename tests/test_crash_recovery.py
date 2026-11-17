"""崩溃注入与重启重试测试（真实子进程 os._exit）。

- 提交前崩溃（exit_before_commit，退出码 86）：事务未提交，数据库无任何痕迹，
  重启后用同一 request_id 重试应当 *首次成功*，且只产生一条绑定/审计。
- 提交后崩溃（exit_after_commit，退出码 87）：事务已持久化但响应丢失，
  重启后同 request_id 重放返回既有结果，不重复绑定。
- 软崩溃（raise_before_commit）：事务回滚，进程存活并回传 injected_crash。

每个崩溃动作都在独立 spawn 进程执行，父进程随后新建 service 打开同一数据库，
模拟"进程重启"，全程不依赖线程锁。
"""

from __future__ import annotations

import multiprocessing as mp
import os
import unittest

from solution.service import EXIT_AFTER_COMMIT, EXIT_BEFORE_COMMIT
from solution.worker import worker_main
from tests._helpers import (
    AUDIENCE,
    ISSUER_A,
    ISSUER_B,
    build_key_store,
    build_service,
    mint_token,
    new_temp_dir,
)

CTX = mp.get_context("spawn")
SEED = 20261117


def _crash_worker_entry(payload, queue):
    # crash 场景不需要屏障
    worker_main(payload, None, queue)


class CrashRecoveryTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = new_temp_dir()
        self.db = os.path.join(self.tmp, "crash.db")
        self.key_store = build_key_store()
        self.svc = build_service(self.db, rng_index=21, key_store=self.key_store)

    def tearDown(self):
        self.svc.close()

    def _payload(self, worker_index, steps, crash_plan):
        return {
            "db_path": self.db,
            "keys": [
                {"issuer": iss, "secret_hex": self.key_store.secret_of(iss).hex()}
                for iss in self.key_store.issuers()
            ],
            "clock_start": 1_700_000_000,
            "seed_base": SEED,
            "worker_index": worker_index,
            "audience": AUDIENCE,
            "crash_plan": crash_plan,
            "vars": {},
            "steps": steps,
        }

    def _start_crash_process(self, payload, *, queue_timeout=30):
        queue = CTX.Queue()
        proc = CTX.Process(target=_crash_worker_entry, args=(payload, queue),
                           name="crash-worker")
        proc.start()
        try:
            reported = queue.get(timeout=queue_timeout)
        except Exception:  # noqa: BLE001 - os._exit 硬崩溃不会写队列
            reported = ("crashed", {"reason": "no queue message"})
        proc.join(20)
        return proc, reported

    def _bootstrap(self, account_id="acct_c", password="pw-c", issuer=ISSUER_A):
        self.svc.create_account("req-acct", account_id, "Crash", password)
        session = self.svc.login("req-login", account_id, password)["session_token"]
        ch = self.svc.start_challenge("req-ch", account_id, session, issuer)
        token = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                           issuer, f"sub-{account_id}", ch["nonce"])
        return account_id, session, ch, token


class HardCrashBeforeCommitTest(CrashRecoveryTestBase):
    def test_exit_before_commit_leaves_no_trace_and_retry_succeeds(self):
        account_id, session, ch, token = self._bootstrap()
        step = {"op": "complete_challenge", "request_id": "req-crash-link",
                "challenge_id": ch["challenge_id"], "session_token": session,
                "assertion_token": token}
        payload = self._payload(
            31, [step],
            {"complete_challenge.before_commit": "exit_before_commit"},
        )
        proc, reported = self._start_crash_process(payload)
        # 硬崩溃证据：退出码 86，且队列无成功消息
        self.assertEqual(proc.exitcode, EXIT_BEFORE_COMMIT)
        self.assertEqual(reported[0], "crashed")

        # 重启视角：事务完全没留下痕迹
        self.assertIsNone(self.svc.find_active_identity(ISSUER_A, f"sub-{account_id}"))
        self.assertEqual(self.svc.list_audit(request_id="req-crash-link"), [])
        self.assertEqual(
            self.svc.conn.execute(
                "SELECT COUNT(*) FROM idempotency_requests WHERE request_id=?",
                ("req-crash-link",),
            ).fetchone()[0],
            0,
        )
        challenge = self.svc.list_challenges(account_id)[0]
        self.assertEqual(challenge["status"], "pending")

        # 模拟重启：全新 service 打开同一数据库，凭同一 request_id 重试
        restarted = build_service(self.db, rng_index=22, key_store=self.key_store)
        try:
            result = restarted.complete_challenge(
                "req-crash-link", ch["challenge_id"], session, token
            )
        finally:
            restarted.close()
        self.assertEqual(result["status"], "linked")
        self.assertFalse(result["replayed"])
        # 终态唯一
        identity = self.svc.find_active_identity(ISSUER_A, f"sub-{account_id}")
        self.assertIsNotNone(identity)
        self.assertEqual(identity["account_id"], account_id)
        self.assertEqual(len(self.svc.list_audit(request_id="req-crash-link")), 1)


class HardCrashAfterCommitTest(CrashRecoveryTestBase):
    def test_exit_after_commit_persists_and_retry_is_idempotent(self):
        account_id, session, ch, token = self._bootstrap(issuer=ISSUER_B)
        step = {"op": "complete_challenge", "request_id": "req-crash-link2",
                "challenge_id": ch["challenge_id"], "session_token": session,
                "assertion_token": token}
        payload = self._payload(
            32, [step],
            {"complete_challenge.after_commit": "exit_after_commit"},
        )
        proc, reported = self._start_crash_process(payload)
        self.assertEqual(proc.exitcode, EXIT_AFTER_COMMIT)
        self.assertEqual(reported[0], "crashed")

        # 提交已持久化：绑定与审计都在，挑战已消费
        identity = self.svc.find_active_identity(ISSUER_B, f"sub-{account_id}")
        self.assertIsNotNone(identity)
        first_link_id = identity["link_id"]
        self.assertEqual(len(self.svc.list_audit(request_id="req-crash-link2")), 1)
        self.assertEqual(self.svc.list_challenges(account_id)[0]["status"], "consumed")

        # 重启重试：拿到同 request_id 的既有结果，标记 replayed，不产生第二份数据
        restarted = build_service(self.db, rng_index=23, key_store=self.key_store)
        try:
            retry = restarted.complete_challenge(
                "req-crash-link2", ch["challenge_id"], session, token
            )
        finally:
            restarted.close()
        self.assertTrue(retry["replayed"])
        self.assertEqual(retry["link_id"], first_link_id)
        self.assertEqual(
            self.svc.conn.execute(
                "SELECT COUNT(*) FROM external_identities WHERE active=1"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(len(self.svc.list_audit(request_id="req-crash-link2")), 1)


class SoftCrashRollbackTest(CrashRecoveryTestBase):
    def test_raise_before_commit_rolls_back_and_process_survives(self):
        account_id, session, ch, token = self._bootstrap()
        step = {"op": "complete_challenge", "request_id": "req-soft-link",
                "challenge_id": ch["challenge_id"], "session_token": session,
                "assertion_token": token}
        payload = self._payload(
            33, [step],
            {"complete_challenge.before_commit": "raise_before_commit"},
        )
        proc, reported = self._start_crash_process(payload)
        self.assertEqual(proc.exitcode, 0)
        self.assertEqual(reported[0], "injected_crash")

        self.assertIsNone(self.svc.find_active_identity(ISSUER_A, f"sub-{account_id}"))
        self.assertEqual(self.svc.list_audit(request_id="req-soft-link"), [])
        self.assertEqual(self.svc.list_challenges(account_id)[0]["status"], "pending")


class CrashAtOtherOperationsTest(CrashRecoveryTestBase):
    def test_unlink_crash_before_commit_preserves_binding(self):
        account_id, session, ch, token = self._bootstrap()
        linked = self.svc.complete_challenge(
            "req-link", ch["challenge_id"], session, token
        )
        step = {"op": "unlink", "request_id": "req-unlink-crash",
                "link_id": linked["link_id"], "session_token": session}
        payload = self._payload(
            34, [step], {"unlink.before_commit": "exit_before_commit"}
        )
        proc, _reported = self._start_crash_process(payload)
        self.assertEqual(proc.exitcode, EXIT_BEFORE_COMMIT)
        # 解绑未生效
        self.assertEqual(len(self.svc.list_identities(account_id)), 1)
        self.assertEqual(self.svc.list_audit(event_type="identity_unlinked"), [])

    def test_disable_crash_after_commit_survives_restart(self):
        account_id, session, _ch, _token = self._bootstrap()
        step = {"op": "disable_account", "request_id": "req-disable-crash",
                "account_id": account_id, "session_token": session}
        payload = self._payload(
            35, [step], {"disable_account.after_commit": "exit_after_commit"}
        )
        proc, _reported = self._start_crash_process(payload)
        self.assertEqual(proc.exitcode, EXIT_AFTER_COMMIT)
        # 禁用已持久化，重启后仍禁用
        self.assertFalse(self.svc.get_account(account_id)["enabled"])
        from solution.errors import AccountDisabled
        with self.assertRaises(AccountDisabled):
            self.svc.login("req-probe", account_id, "pw-c")
        # 同 request_id 重放返回禁用结果而不是重复执行
        restarted = build_service(self.db, rng_index=24, key_store=self.key_store)
        try:
            replay = restarted.disable_account(
                "req-disable-crash", account_id, session
            )
        finally:
            restarted.close()
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            len(self.svc.list_audit(request_id="req-disable-crash")), 1
        )


if __name__ == "__main__":
    unittest.main()
