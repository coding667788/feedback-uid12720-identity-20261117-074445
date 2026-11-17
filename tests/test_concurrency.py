"""真实跨进程并发测试（Windows spawn + multiprocessing.Barrier）。

这里的每个竞态场景都由两个 *独立操作系统进程* 复现：
- 每个进程各自打开独立 SQLite 连接，不共享任何 Python 锁；
- 所有进程（含父进程）在同一个 Barrier 上对齐后同时进入写事务；
- 最终一致性只由数据库（WAL 写锁 + 部分唯一索引 + 单事务原子提交）保证。

断言具体胜者数量、错误码、数据库终态与审计行数，而不是打印成功。
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
import unittest

from solution.idp import IssuerKeyStore
from solution.worker import worker_main
from tests._helpers import (
    AUDIENCE,
    ISSUER_A,
    ISSUER_B,
    build_key_store,
    build_service,
    mint_token,
    new_temp_dir,
    seeded_rng,
)

CTX = mp.get_context("spawn")
SEED = 20261117


def _worker_entry(payload, barrier, queue):
    """spawn 入口（模块级函数）。"""
    worker_main(payload, barrier, queue)


def _ordered_entry(payload, barrier, queue, sync_registry):
    """带 Event 门控注册表的 spawn 入口。"""
    worker_main(payload, barrier, queue, sync_registry=sync_registry)


class TwoProcessTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = new_temp_dir()
        self.db = os.path.join(self.tmp, "race.db")
        self.key_store = build_key_store()
        self.svc = build_service(self.db, rng_index=11, key_store=self.key_store)

    def tearDown(self):
        self.svc.close()

    def _payload(self, worker_index, steps, variables, *, crash_plan=None):
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
            "vars": dict(variables),
            "steps": steps,
        }

    def _run_pair(self, payload_a, payload_b, *, timeout=60):
        """启动两个真实进程，三方可入屏障（两子进程+父进程）同时放行。"""
        barrier = CTX.Barrier(3)
        queue = CTX.Queue()
        p_a = CTX.Process(target=_worker_entry, args=(payload_a, barrier, queue),
                          name="race-worker-a")
        p_b = CTX.Process(target=_worker_entry, args=(payload_b, barrier, queue),
                          name="race-worker-b")
        p_a.start()
        p_b.start()
        # 证据：确为两个独立进程，且与父进程 PID 都不同
        self.assertNotIn(p_a.pid, (os.getpid(), p_b.pid))
        self.assertNotIn(p_b.pid, (os.getpid(), p_a.pid))
        barrier.wait(timeout)
        results = [queue.get(timeout=timeout), queue.get(timeout=timeout)]
        p_a.join(15)
        p_b.join(15)
        self.assertEqual(p_a.exitcode, 0, f"worker-a 异常: {results}")
        self.assertEqual(p_b.exitcode, 0, f"worker-b 异常: {results}")
        for kind, body in results:
            self.assertEqual(kind, "ok", f"子进程报错: {body}")
        return [body for _kind, body in results]

    def _setup_two_accounts(self):
        self.svc.create_account("req-a", "acct_a", "Alice", "pw-a")
        self.svc.create_account("req-b", "acct_b", "Bob", "pw-b")
        sess_a = self.svc.login("req-la", "acct_a", "pw-a")["session_token"]
        sess_b = self.svc.login("req-lb", "acct_b", "pw-b")["session_token"]
        return sess_a, sess_b


class ProcessIsolationTest(TwoProcessTestBase):
    def test_spawn_context_and_distinct_pids(self):
        self.assertEqual(CTX.get_start_method(), "spawn")
        sess_a, sess_b = self._setup_two_accounts()
        # 两个进程各做一次只读 list，验证连通性与 PID 隔离
        pa = self._payload(1, [{"op": "list_identities", "account_id": "acct_a"}], {})
        pb = self._payload(2, [{"op": "list_identities", "account_id": "acct_b"}], {})
        bodies = self._run_pair(pa, pb)
        for body in bodies:
            self.assertEqual(body["steps"][0]["outcome"]["status"], "ok")


class ConcurrentRaceBindingTest(TwoProcessTestBase):
    def test_same_external_identity_single_winner(self):
        sess_a, sess_b = self._setup_two_accounts()
        ch_a = self.svc.start_challenge("req-cha", "acct_a", sess_a, ISSUER_A)
        ch_b = self.svc.start_challenge("req-chb", "acct_b", sess_b, ISSUER_A)
        # 同一 (issuer, subject)，各自挑战 nonce 不同 -> 两个合法断言
        tok_a = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "contended-1", ch_a["nonce"])
        tok_b = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "contended-1", ch_b["nonce"])
        pa = self._payload(
            1,
            [{"op": "complete_challenge", "request_id": "req-race-a",
              "challenge_id": ch_a["challenge_id"], "session_token": sess_a,
              "assertion_token": tok_a}],
            {},
        )
        pb = self._payload(
            2,
            [{"op": "complete_challenge", "request_id": "req-race-b",
              "challenge_id": ch_b["challenge_id"], "session_token": sess_b,
              "assertion_token": tok_b}],
            {},
        )
        bodies = self._run_pair(pa, pb)
        statuses = sorted(b["steps"][0]["outcome"]["status"] for b in bodies)
        errors = [b["steps"][0]["outcome"]["error"] for b in bodies]
        self.assertEqual(statuses, ["error", "ok"])
        self.assertIn("identity_already_bound", errors)

        # 数据库终态：活跃绑定全局唯一
        identity = self.svc.find_active_identity(ISSUER_A, "contended-1")
        self.assertIsNotNone(identity)
        self.assertIn(identity["account_id"], ("acct_a", "acct_b"))
        self.assertEqual(
            self.svc.conn.execute(
                "SELECT COUNT(*) FROM external_identities WHERE active=1"
            ).fetchone()[0],
            1,
        )
        # 关联写入与审计同事务：恰好一条 identity_linked
        linked = self.svc.list_audit(event_type="identity_linked")
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0]["account_id"], identity["account_id"])
        # 败者账号的挑战保持 pending（它的事务整体回滚，未消费挑战）
        winner = identity["account_id"]
        loser = "acct_b" if winner == "acct_a" else "acct_a"
        loser_challenges = self.svc.list_challenges(loser)
        self.assertTrue(all(c["status"] == "pending" for c in loser_challenges))

    def test_race_repeated_runs_always_single_winner(self):
        """重复 5 轮独立抢绑，每轮都必须恰好一个胜者（无死锁、无双写）。"""
        for round_idx in range(5):
            subject = f"contended-repeat-{round_idx}"
            sess_a, sess_b = self._setup_two_accounts()
            ch_a = self.svc.start_challenge(f"req-cha-{round_idx}", "acct_a", sess_a, ISSUER_A)
            ch_b = self.svc.start_challenge(f"req-chb-{round_idx}", "acct_b", sess_b, ISSUER_A)
            tok_a = mint_token(self.key_store, self.svc.clock, seeded_rng(100 + round_idx),
                               ISSUER_A, subject, ch_a["nonce"])
            tok_b = mint_token(self.key_store, self.svc.clock, seeded_rng(200 + round_idx),
                               ISSUER_A, subject, ch_b["nonce"])
            pa = self._payload(
                100 + round_idx,
                [{"op": "complete_challenge", "request_id": f"req-ra-{round_idx}",
                  "challenge_id": ch_a["challenge_id"], "session_token": sess_a,
                  "assertion_token": tok_a}],
                {},
            )
            pb = self._payload(
                200 + round_idx,
                [{"op": "complete_challenge", "request_id": f"req-rb-{round_idx}",
                  "challenge_id": ch_b["challenge_id"], "session_token": sess_b,
                  "assertion_token": tok_b}],
                {},
            )
            bodies = self._run_pair(pa, pb)
            ok_count = sum(
                1 for b in bodies if b["steps"][0]["outcome"]["status"] == "ok"
            )
            self.assertEqual(ok_count, 1, f"第 {round_idx} 轮胜者数量异常: {bodies}")
            self.assertIsNotNone(self.svc.find_active_identity(ISSUER_A, subject))


class ConcurrentDoubleUnlinkTest(TwoProcessTestBase):
    def test_concurrent_unlink_of_last_two_methods_one_winner(self):
        # 带口令引导建立两个外部身份
        self.svc.create_account("req-acct", "acct_fed", "Erin", "pw-bootstrap")
        s1 = self.svc.login("req-l1", "acct_fed", "pw-bootstrap")["session_token"]
        s2 = self.svc.login("req-l2", "acct_fed", "pw-bootstrap")["session_token"]
        ch1 = self.svc.start_challenge("req-ch1", "acct_fed", s1, ISSUER_A)
        ch2 = self.svc.start_challenge("req-ch2", "acct_fed", s2, ISSUER_B)
        t1 = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                        ISSUER_A, "fed-a", ch1["nonce"])
        t2 = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                        ISSUER_B, "fed-b", ch2["nonce"])
        l1 = self.svc.complete_challenge("req-link1", ch1["challenge_id"], s1, t1)
        l2 = self.svc.complete_challenge("req-link2", ch2["challenge_id"], s2, t2)
        # 转为纯联邦账号：仅剩两个外部身份
        self.svc.remove_local_password("acct_fed")
        self.assertEqual(len(self.svc.list_identities("acct_fed")), 2)

        pa = self._payload(
            3,
            [{"op": "unlink", "request_id": "req-unlink-a",
              "link_id": l1["link_id"], "session_token": s1}],
            {},
        )
        pb = self._payload(
            4,
            [{"op": "unlink", "request_id": "req-unlink-b",
              "link_id": l2["link_id"], "session_token": s2}],
            {},
        )
        bodies = self._run_pair(pa, pb)
        statuses = sorted(b["steps"][0]["outcome"]["status"] for b in bodies)
        errors = [b["steps"][0]["outcome"]["error"] for b in bodies]
        self.assertEqual(statuses, ["error", "ok"])
        self.assertIn("last_login_method", errors)

        # 终态：恰好保留一个可用登录方式
        active = self.svc.list_identities("acct_fed")
        self.assertEqual(len(active), 1)
        unlink_events = self.svc.list_audit(event_type="identity_unlinked")
        self.assertEqual(len(unlink_events), 1)


class ConcurrentIdempotencyTest(TwoProcessTestBase):
    def test_same_request_id_concurrent_first_wins_second_replays(self):
        sess_a, _ = self._setup_two_accounts()
        ch = self.svc.start_challenge("req-ch", "acct_a", sess_a, ISSUER_A)
        token = mint_token(self.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "idem-race", ch["nonce"])
        step = {"op": "complete_challenge", "request_id": "req-shared-idem",
                "challenge_id": ch["challenge_id"], "session_token": sess_a,
                "assertion_token": token}
        # 两个进程以完全相同的参数和 request_id 同时打进来
        pa = self._payload(5, [dict(step)], {})
        pb = self._payload(6, [dict(step)], {})
        bodies = self._run_pair(pa, pb)
        outcomes = [b["steps"][0]["outcome"] for b in bodies]
        self.assertTrue(all(o["status"] == "ok" for o in outcomes))
        link_ids = {o["data"]["link_id"] for o in outcomes}
        self.assertEqual(len(link_ids), 1)
        replayed = sorted(bool(o["data"].get("replayed")) for o in outcomes)
        self.assertEqual(replayed, [False, True])
        # 只有一条绑定、一条审计
        self.assertEqual(
            self.svc.conn.execute(
                "SELECT COUNT(*) FROM external_identities WHERE active=1"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(len(self.svc.list_audit(request_id="req-shared-idem")), 1)


class DisableVersusLinkLinearizationTest(TwoProcessTestBase):
    def _prepare(self, tag):
        account_id = f"acct_lin_{tag}"
        self.svc.create_account(f"req-acct-{tag}", account_id, "Lin", "pw-lin")
        sess = self.svc.login(f"req-login-{tag}", account_id, "pw-lin")["session_token"]
        ch = self.svc.start_challenge(f"req-ch-{tag}", account_id, sess, ISSUER_A)
        token = mint_token(self.key_store, self.svc.clock, seeded_rng(700 + len(tag)),
                           ISSUER_A, f"lin-sub-{tag}", ch["nonce"])
        return account_id, sess, ch, token

    def _run_ordered(self, tag: str, first: str):
        """用 Event 门控确定性地安排两个真实进程的提交顺序。

        first="disable"：禁用进程先提交，关联进程在门控 Event 上等待，
                         禁用提交并 set 事件后才放行关联；
        first="link"：反过来，关联先提交，禁用等待。
        门控点在业务步骤 *之前*，因此先放行的进程必然先拿到写锁先提交，
        不依赖 sleep 或调度抖动。
        """
        account_id, sess, ch, token = self._prepare(tag)
        link_step = {"op": "complete_challenge", "request_id": f"req-link-{tag}",
                     "challenge_id": ch["challenge_id"], "session_token": sess,
                     "assertion_token": token}
        disable_step = {"op": "disable_account", "request_id": f"req-dis-{tag}",
                        "account_id": account_id, "session_token": sess}

        gate_link = CTX.Event()
        gate_disable = CTX.Event()
        barrier = CTX.Barrier(3)
        queue = CTX.Queue()
        registry = {"gate_link": gate_link, "gate_disable": gate_disable}

        # 每个进程：先在总屏障对齐，再等自己的门控，再做业务
        link_steps = [{"op": "_sync", "wait": "gate_link"}, link_step]
        disable_steps = [{"op": "_sync", "wait": "gate_disable"}, disable_step]
        pa = self._payload(7, link_steps, {})
        pb = self._payload(8, disable_steps, {})
        p_link = CTX.Process(target=_ordered_entry,
                             args=(pa, barrier, queue, registry), name="ordered-link")
        p_dis = CTX.Process(target=_ordered_entry,
                            args=(pb, barrier, queue, registry), name="ordered-disable")
        p_link.start()
        p_dis.start()
        barrier.wait(30)
        # 父进程决定先放哪一边
        if first == "disable":
            gate_disable.set()
            # 等禁用真正落库后再放关联：轮询账号 enabled 标志
            deadline = time.time() + 30
            while time.time() < deadline and self.svc.get_account(account_id)["enabled"]:
                time.sleep(0.01)
            gate_link.set()
        else:
            gate_link.set()
            deadline = time.time() + 30
            while time.time() < deadline and not self.svc.find_active_identity(
                ISSUER_A, f"lin-sub-{tag}"
            ):
                time.sleep(0.01)
            gate_disable.set()

        raw = [queue.get(timeout=30), queue.get(timeout=30)]
        p_link.join(15)
        p_dis.join(15)
        self.assertEqual(p_link.exitcode, 0)
        self.assertEqual(p_dis.exitcode, 0)
        for kind, body in raw:
            if kind != "ok":
                raise AssertionError(f"子进程失败: {body}")
            self.assertEqual(kind, "ok")
        bodies = sorted((body for _kind, body in raw),
                        key=lambda b: b.get("worker_index", 10**9))
        link_outcome = bodies[0]["steps"][-1]["outcome"]
        disable_outcome = bodies[1]["steps"][-1]["outcome"]
        return account_id, f"lin-sub-{tag}", link_outcome, disable_outcome

    def test_both_linearizations_preserve_invariants(self):
        # 顺序 A：禁用先提交 -> 关联必须失败，且无绑定/无关联审计
        acct_a, sub_a, link_a, dis_a = self._run_ordered("a", "disable")
        self.assertEqual(dis_a["status"], "ok")
        self.assertEqual(link_a["status"], "error")
        self.assertIn(link_a["error"], ("account_disabled", "challenge_revoked"))
        self.assertFalse(self.svc.get_account(acct_a)["enabled"])
        self.assertIsNone(self.svc.find_active_identity(ISSUER_A, sub_a))
        self.assertNotIn(
            "identity_linked",
            [e["event_type"] for e in self.svc.list_audit(account_id=acct_a)],
        )

        # 顺序 B：关联先提交 -> 关联成功，随后禁用成功
        acct_b, sub_b, link_b, dis_b = self._run_ordered("b", "link")
        self.assertEqual(link_b["status"], "ok")
        self.assertEqual(dis_b["status"], "ok")
        self.assertFalse(self.svc.get_account(acct_b)["enabled"])
        identity = self.svc.find_active_identity(ISSUER_A, sub_b)
        self.assertIsNotNone(identity)
        self.assertEqual(identity["account_id"], acct_b)
        events = [e["event_type"] for e in self.svc.list_audit(account_id=acct_b)]
        self.assertIn("identity_linked", events)
        self.assertIn("account_disabled", events)
        # 审计按提交顺序线性追加，两类事件都恰好一条，无丢失写
        self.assertEqual(events.count("identity_linked"), 1)
        self.assertEqual(events.count("account_disabled"), 1)

        # 两种顺序下：禁用提交后再启动的新操作都不能成功
        from solution.errors import AccountDisabled
        with self.assertRaises(AccountDisabled):
            self.svc.login("req-probe-b", acct_b, "pw-lin")


if __name__ == "__main__":
    unittest.main()
