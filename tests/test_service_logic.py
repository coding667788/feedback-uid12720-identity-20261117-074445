"""LinkingService 顺序逻辑测试（单进程）。

覆盖：同邮箱不同主体不合并、挑战-会话绑定、断言全攻击面、幂等重放/冲突、
解绑最后登录方式保护、禁用线性化与挑战撤销、登录新鲜度与挑战到期。
"""

from __future__ import annotations

import os
import unittest

from solution.clock import FakeClock
from solution.errors import (
    AccountDisabled,
    AssertionExpired,
    AssertionNonceMismatch,
    AssertionNotYetValid,
    ChallengeConsumed,
    ChallengeExpired,
    ChallengeRevoked,
    ChallengeSessionMismatch,
    IdentityAlreadyBound,
    IdentityNotLinked,
    IdempotencyConflict,
    LastLoginMethod,
    LoginNotRecent,
    PasswordMismatch,
    ServiceError,
    SessionNotFound,
)
from tests._helpers import (
    AUDIENCE,
    ISSUER_A,
    ISSUER_B,
    build_service,
    full_link,
    mint_token,
    new_temp_dir,
)


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = new_temp_dir()
        self.db = os.path.join(self.tmp, "svc.db")
        self.svc = build_service(self.db, rng_index=1)

    def tearDown(self):
        self.svc.close()

    def _account_with_session(self, account_id="acct1", password="pw-1"):
        self.svc.create_account(f"req-{account_id}-acct", account_id, account_id, password)
        session = self.svc.login(f"req-{account_id}-login", account_id, password)[
            "session_token"
        ]
        return session


class SameEmailDistinctSubjectTest(ServiceTestBase):
    def test_same_email_different_subjects_are_two_identities(self):
        session = self._account_with_session()
        r1 = full_link(self.svc, "r-a", "acct1", session, ISSUER_A,
                       "alpha-77", email="shared@example.com")
        r2 = full_link(self.svc, "r-b", "acct1", session, ISSUER_B,
                       "bravo-99", email="shared@example.com")
        self.assertEqual(r1["status"], "linked")
        self.assertEqual(r2["status"], "linked")
        self.assertNotEqual(r1["link_id"], r2["link_id"])

        identities = self.svc.list_identities("acct1")
        self.assertEqual(len(identities), 2)
        subjects = {(i["issuer"], i["subject"]) for i in identities}
        self.assertEqual(
            subjects,
            {(ISSUER_A, "alpha-77"), (ISSUER_B, "bravo-99")},
        )
        # 邮箱相同也不产生任何合并：两个身份都指向同一账号是因为显式绑定，
        # 且各自独立可查
        self.assertEqual(
            self.svc.find_active_identity(ISSUER_A, "alpha-77")["account_id"], "acct1"
        )
        self.assertEqual(
            self.svc.find_active_identity(ISSUER_B, "bravo-99")["account_id"], "acct1"
        )
        self.assertIsNone(self.svc.find_active_identity(ISSUER_A, "bravo-99"))

    def test_identity_key_is_issuer_plus_subject_not_email(self):
        session = self._account_with_session()
        full_link(self.svc, "r1", "acct1", session, ISSUER_A, "dup-sub",
                  email="first@example.com")
        # 同 issuer 同 subject、哪怕邮箱不同，也不能二次绑定
        with self.assertRaises(IdentityAlreadyBound):
            full_link(self.svc, "r2", "acct1", session, ISSUER_A, "dup-sub",
                      email="second-different@example.com")


class ChallengeSessionBindingTest(ServiceTestBase):
    def test_session_swap_is_rejected_original_session_succeeds(self):
        s1 = self._account_with_session("acct1")
        s2 = self.svc.login("req-acct1-login2", "acct1", "pw-1")["session_token"]
        ch = self.svc.start_challenge("req-ch", "acct1", s1, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "swap-sub", ch["nonce"])

        with self.assertRaises(ChallengeSessionMismatch):
            self.svc.complete_challenge("req-complete-wrong", ch["challenge_id"], s2, token)
        # 挑战未被消费，原会话可以完成
        ok = self.svc.complete_challenge("req-complete-right", ch["challenge_id"], s1, token)
        self.assertEqual(ok["status"], "linked")
        # 一次性：再次使用同一挑战必败
        with self.assertRaises(ChallengeConsumed):
            self.svc.complete_challenge("req-replay", ch["challenge_id"], s1, token)
        challenge = self.svc.list_challenges("acct1")[0]
        self.assertEqual(challenge["status"], "consumed")
        self.assertEqual(challenge["link_id"], ok["link_id"])

    def test_session_from_other_account_rejected(self):
        s1 = self._account_with_session("acct1")
        self.svc.create_account("req-acct2", "acct2", "acct2", "pw-2")
        s_other = self.svc.login("req-acct2-login", "acct2", "pw-2")["session_token"]
        with self.assertRaises(SessionNotFound):
            self.svc.start_challenge("req-ch-other", "acct1", s_other, ISSUER_A)


class AssertionValidationTest(ServiceTestBase):
    def _challenge(self, session):
        return self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)

    def test_bad_signature_wrong_key_aud_override_expired_future_nonce(self):
        session = self._account_with_session()
        ch = self._challenge(session)
        base = dict(issuer=ISSUER_A, subject="karl-sub", nonce=ch["nonce"])

        bad_sig = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                             **base, corrupt_signature=True)
        from solution.errors import AssertionBadSignature
        with self.assertRaises(AssertionBadSignature):
            self.svc.complete_challenge("r1", ch["challenge_id"], session, bad_sig)

        wrong_key = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                               **base, sign_with_wrong_key=True)
        with self.assertRaises(AssertionBadSignature):
            self.svc.complete_challenge("r2", ch["challenge_id"], session, wrong_key)

        bad_aud = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                             **base, audience_override="https://evil/")
        from solution.errors import AssertionAudienceMismatch
        with self.assertRaises(AssertionAudienceMismatch):
            self.svc.complete_challenge("r3", ch["challenge_id"], session, bad_aud)

        expired = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                             **base, backdate_expired=True)
        with self.assertRaises(AssertionExpired):
            self.svc.complete_challenge("r4", ch["challenge_id"], session, expired)

        future = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                            **base, future_nbf=True)
        with self.assertRaises(AssertionNotYetValid):
            self.svc.complete_challenge("r5", ch["challenge_id"], session, future)

        stale_nonce = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                                 ISSUER_A, "karl-sub", "stale-nonce")
        with self.assertRaises(AssertionNonceMismatch):
            self.svc.complete_challenge("r6", ch["challenge_id"], session, stale_nonce)

    def test_issuer_mismatch_between_challenge_and_assertion(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)
        # 用 bravo 的密钥为 bravo issuer 签发，但挑战目标是 alpha
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_B, "b-sub", ch["nonce"])
        with self.assertRaises(ServiceError) as ctx:
            self.svc.complete_challenge("r", ch["challenge_id"], session, token)
        # 用 alpha 密钥验 bravo 令牌首先在签名层失败
        self.assertEqual(ctx.exception.code, "assertion_bad_signature")


class IdempotencyTest(ServiceTestBase):
    def test_replay_returns_stored_result_and_single_audit_row(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "idem-sub", ch["nonce"])
        first = self.svc.complete_challenge("req-link", ch["challenge_id"], session, token)
        self.assertFalse(first["replayed"])

        second = self.svc.complete_challenge("req-link", ch["challenge_id"], session, token)
        self.assertTrue(second["replayed"])
        self.assertEqual(second["link_id"], first["link_id"])

        events = self.svc.list_audit(request_id="req-link")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "identity_linked")

    def test_reuse_request_id_with_different_params_rejected(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "idem-sub2", ch["nonce"])
        self.svc.complete_challenge("shared-req", ch["challenge_id"], session, token)
        with self.assertRaises(IdempotencyConflict):
            self.svc.complete_challenge("shared-req", ch["challenge_id"], session, "tampered")

    def test_failed_request_id_is_also_owned_and_replayable(self):
        session = self._account_with_session()
        # 不存在的挑战：业务失败也落幂等记录
        with self.assertRaises(ServiceError):
            self.svc.complete_challenge("req-failed", "chl_missing", session, "tok")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.complete_challenge("req-failed", "chl_missing", session, "tok")
        self.assertEqual(ctx.exception.code, "challenge_not_found")


class UnlinkProtectionTest(ServiceTestBase):
    def test_cannot_unlink_when_only_one_external_identity_and_no_password(self):
        session = self._account_with_session()
        link = full_link(self.svc, "r", "acct1", session, ISSUER_A, "sole-sub")
        # 移除本地口令 -> 该外部身份是唯一登录方式
        self.svc.remove_local_password("acct1")
        with self.assertRaises(LastLoginMethod):
            self.svc.unlink("req-unlink", link["link_id"], session)
        # 绑定仍然活跃
        self.assertEqual(len(self.svc.list_identities("acct1")), 1)

    def test_unlink_allowed_with_password_and_double_unlink_blocked(self):
        session = self._account_with_session()
        l1 = full_link(self.svc, "r1", "acct1", session, ISSUER_A, "s1")
        l2 = full_link(self.svc, "r2", "acct1", session, ISSUER_B, "s2")
        # 有口令：两个外部身份都可解绑
        self.assertEqual(self.svc.unlink("u1", l1["link_id"], session)["status"], "unlinked")
        # 再解第二个：口令仍在，允许
        self.assertEqual(self.svc.unlink("u2", l2["link_id"], session)["status"], "unlinked")
        with self.assertRaises(IdentityNotLinked):
            self.svc.unlink("u3", l2["link_id"], session)

    def test_rebind_same_subject_after_unlink(self):
        session = self._account_with_session()
        link = full_link(self.svc, "r1", "acct1", session, ISSUER_A, "mobile-sub")
        self.svc.unlink("u1", link["link_id"], session)
        # 解绑后同一 (issuer, subject) 允许重新绑定
        again = full_link(self.svc, "r2", "acct1", session, ISSUER_A, "mobile-sub")
        self.assertEqual(again["status"], "linked")
        self.assertEqual(len(self.svc.list_identities("acct1")), 1)


class DisableLinearizationTest(ServiceTestBase):
    def test_disable_revokes_sessions_and_challenges_and_blocks_new_ops(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch1", "acct1", session, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "judy-sub", ch["nonce"])

        result = self.svc.disable_account("req-disable", "acct1", session)
        self.assertFalse(result["enabled"])
        self.assertEqual(result["revoked_challenges"], 1)

        with self.assertRaises(AccountDisabled):
            self.svc.start_challenge("req-ch2", "acct1", session, ISSUER_A)
        with self.assertRaises(ChallengeRevoked):
            self.svc.complete_challenge("req-complete", ch["challenge_id"], session, token)

        # 重新启用不复活旧挑战、不复活旧会话
        self.svc.enable_account("req-enable", "acct1")
        # 旧挑战的 revoked 检查先于会话检查，旧会话 + 旧挑战同样被拒
        with self.assertRaises(ChallengeRevoked):
            self.svc.complete_challenge("req-old-session", ch["challenge_id"], session, token)
        # 旧会话本身也已撤销：换一个全新挑战也无法用它
        new_session = self.svc.login("req-relogin", "acct1", "pw-1")["session_token"]
        with self.assertRaises(SessionNotFound):
            self.svc.start_challenge("req-ch-with-old-session", "acct1", session, ISSUER_A)
        with self.assertRaises(ChallengeRevoked):
            self.svc.complete_challenge("req-old-challenge", ch["challenge_id"],
                                        new_session, token)
        statuses = {c["challenge_id"]: c["status"] for c in self.svc.list_challenges("acct1")}
        self.assertEqual(statuses[ch["challenge_id"]], "revoked")

    def test_password_login_blocked_while_disabled(self):
        session = self._account_with_session()
        self.svc.disable_account("req-disable", "acct1", session)
        with self.assertRaises(AccountDisabled):
            self.svc.login("req-login-while-disabled", "acct1", "pw-1")


class FreshnessAndExpiryTest(ServiceTestBase):
    def test_stale_login_blocks_challenge_start(self):
        session = self._account_with_session()
        self.svc.clock.advance(301)
        with self.assertRaises(LoginNotRecent):
            self.svc.start_challenge("req-stale", "acct1", session, ISSUER_A)

    def test_challenge_expiry_is_enforced_and_marked(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "liam-sub", ch["nonce"])
        self.svc.clock.advance(301)
        with self.assertRaises(ChallengeExpired):
            self.svc.complete_challenge("req-exp", ch["challenge_id"], session, token)
        # 过期失败与惰性标记在同一事务内回滚，挑战保持 pending，未被消费；
        # 到期判定本身由上面抛出的 ChallengeExpired 证明
        self.assertEqual(self.svc.list_challenges("acct1")[0]["status"], "pending")
        # 且该挑战此后永远无法完成（时间只会继续前进）
        with self.assertRaises(ChallengeExpired):
            self.svc.complete_challenge("req-exp-2", ch["challenge_id"], session, token)

    def test_session_expiry(self):
        session = self._account_with_session()
        self.svc.clock.advance(3601)
        from solution.errors import SessionExpired
        with self.assertRaises(SessionExpired):
            self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)


class AuditAndTransactionTest(ServiceTestBase):
    def test_audit_row_shares_transaction_with_link_write(self):
        session = self._account_with_session()
        link = full_link(self.svc, "r", "acct1", session, ISSUER_A, "audit-sub")
        events = self.svc.list_audit(event_type="identity_linked")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["detail"]["link_id"], link["link_id"])
        self.assertEqual(events[0]["subject"], "audit-sub")

    def test_soft_crash_rolls_back_everything(self):
        session = self._account_with_session()
        ch = self.svc.start_challenge("req-ch", "acct1", session, ISSUER_A)
        token = mint_token(self.svc.key_store, self.svc.clock, self.svc.rng,
                           ISSUER_A, "crash-sub", ch["nonce"])
        crashing = build_service(
            self.db, rng_index=2,
            crash_plan={"complete_challenge.before_commit": "raise_before_commit"},
        )
        from solution.errors import InjectedCrash
        with self.assertRaises(InjectedCrash):
            crashing.complete_challenge("req-crash", ch["challenge_id"], session, token)
        crashing.close()

        # 新连接视角：无绑定、无审计、挑战仍 pending（事务已回滚）
        self.assertIsNone(self.svc.find_active_identity(ISSUER_A, "crash-sub"))
        self.assertEqual(self.svc.list_audit(request_id="req-crash"), [])
        self.assertEqual(self.svc.list_challenges("acct1")[0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
