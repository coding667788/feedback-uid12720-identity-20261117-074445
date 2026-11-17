"""账号关联服务核心。

设计要点对照题目要求：

1. 外部身份唯一键 = (issuer, subject)，email 仅存展示字段，无任何基于邮箱
   的合并逻辑。发起关联 (start_challenge) 必须持有目标内部账号的有效且
   "近期登录"的浏览器会话；挑战同时绑定账号、目标 issuer、该浏览器会话、
   nonce 与到期时间；complete 时断言的 nonce/issuer/aud 必须与挑战一致，
   成功后挑战置为 consumed，一次性。
2. 所有写操作走 ``BEGIN IMMEDIATE`` 单事务：关联写入、挑战消费、幂等记录、
   审计事件在同一事务提交；(issuer, subject) 部分唯一索引由数据库兜底，
   跨进程抢绑只有一个胜者。request_id 幂等：同参重放返回首次结果，换参
   复用同一 request_id 返回 idempotency_conflict。
3. 解绑前统计可用登录方式（外部活跃绑定数 + 本地口令），为 1 时拒绝；
   禁用与关联/解绑在同一写锁队列里按提交顺序线性化；禁用即撤销全部会话
   与待处理挑战，重新启用不会让旧挑战复活。
4. 时钟通过构造函数注入；崩溃点通过 crash_plan 注入，支持进程退出
   （提交前/提交后）与抛异常两种模式，供真实多进程测试复现崩溃-重启。
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
from typing import Any, Callable

from .clock import Clock, SystemClock
from .crypto import (
    b64url_encode,
    canonical_hash,
    hash_password,
    verify_assertion_signature,
    verify_password,
)
from .db import connect, initialize_database, transaction
from .errors import (
    AccountAlreadyExists,
    AccountDisabled,
    AccountNotFound,
    AssertionAudienceMismatch,
    AssertionBadSignature,
    AssertionExpired,
    AssertionNonceMismatch,
    AssertionNotYetValid,
    ChallengeConsumed,
    ChallengeExpired,
    ChallengeIssuerMismatch,
    ChallengeNotFound,
    ChallengeRevoked,
    ChallengeSessionMismatch,
    IdentityAlreadyBound,
    IdentityNotLinked,
    IdempotencyConflict,
    InjectedCrash,
    LastLoginMethod,
    LoginNotRecent,
    PasswordMismatch,
    ServiceError,
    SessionExpired,
    SessionNotFound,
    UnknownIssuerError,
)
from .idp import IssuerKeyStore

# 崩溃退出码（测试据此判断是"注入崩溃"而非其他失败）
EXIT_BEFORE_COMMIT = 86
EXIT_AFTER_COMMIT = 87


class CrashInjection:
    """崩溃点注入器。

    plan 形如::

        {"complete_challenge.before_commit": "exit_before_commit",
         "complete_challenge.after_commit":  "exit_after_commit",
         "unlink.before_commit":             "raise_before_commit"}

    - exit_before_commit : 以 86 退出码 os._exit，当前事务从未提交
    - exit_after_commit  : 事务已 COMMIT 并持久化后以 87 退出，模拟"响应丢失"
    - raise_before_commit: 抛 InjectedCrash，事务回滚（同进程可捕获的软崩溃）
    """

    def __init__(self, plan: dict[str, str] | None = None):
        self.plan = dict(plan or {})

    def hook(self, point: str) -> None:
        mode = self.plan.get(point)
        if mode is None:
            return
        if mode == "exit_before_commit":
            os._exit(EXIT_BEFORE_COMMIT)
        if mode == "exit_after_commit":
            os._exit(EXIT_AFTER_COMMIT)
        if mode == "raise_before_commit":
            raise InjectedCrash(f"注入崩溃点: {point}")
        raise ValueError(f"未知崩溃模式: {mode!r}（点 {point}）")


class LinkingService:
    def __init__(
        self,
        db_path: str,
        key_store: IssuerKeyStore,
        clock: Clock | None = None,
        *,
        audience: str = "local-linking-service",
        rng: random.Random | None = None,
        login_freshness_seconds: int = 300,
        session_ttl_seconds: int = 3_600,
        challenge_ttl_seconds: int = 300,
        crash_plan: dict[str, str] | None = None,
        auto_init: bool = True,
    ):
        self.db_path = db_path
        self.key_store = key_store
        self.clock = clock or SystemClock()
        self.audience = audience
        self.rng = rng or random.Random()
        self.login_freshness = login_freshness_seconds
        self.session_ttl = session_ttl_seconds
        self.challenge_ttl = challenge_ttl_seconds
        self.crash = CrashInjection(crash_plan)
        # 本服务实例内单调递增的 ID 计数器；与实例标签混合，保证同一数据库上
        # 多个进程（各自独立的 service 实例、可能持有相同种子的 RNG）生成的
        # 主键全局唯一、不会碰撞
        self._id_counter = 0
        self._instance_tag = b64url_encode(self.rng.randbytes(6))
        if auto_init:
            initialize_database(db_path)
        self.conn = connect(db_path)

    # ------------------------------------------------------------------ 基础
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "LinkingService":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _id(self, prefix: str, n: int = 12) -> str:
        # 随机字节 + 实例标签 + 进程 PID + 实例内单调计数器，整体编码不截断，
        # 保证跨进程、跨实例主键唯一，不依赖 RNG 流不重复
        self._id_counter += 1
        raw = self.rng.randbytes(n)
        raw += b"|" + self._instance_tag.encode("ascii")
        raw += f"|{os.getpid()}|{self._id_counter}".encode("ascii")
        return f"{prefix}_{b64url_encode(raw)}"

    def _audit(
        self,
        c: sqlite3.Connection,
        event_type: str,
        *,
        account_id: str | None = None,
        request_id: str | None = None,
        issuer: str | None = None,
        subject: str | None = None,
        challenge_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> str:
        event_id = self._id("evt", 12)
        c.execute(
            "INSERT INTO audit_events (event_id,event_type,account_id,request_id,"
            "issuer,subject,challenge_id,detail,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                event_type,
                account_id,
                request_id,
                issuer,
                subject,
                challenge_id,
                json.dumps(detail or {}, sort_keys=True, ensure_ascii=False),
                self.clock.now(),
            ),
        )
        return event_id

    def _idempotent(
        self,
        request_id: str,
        operation: str,
        params: dict,
        fn: Callable[[sqlite3.Connection], dict],
    ) -> dict:
        """幂等包装：request_id 唯一、参数指纹校验、同事务落盘。"""
        fingerprint = canonical_hash(params)
        with transaction(self.conn) as c:
            row = c.execute(
                "SELECT operation, fingerprint, status, response FROM "
                "idempotency_requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if row["fingerprint"] != fingerprint or row["operation"] != operation:
                    raise IdempotencyConflict(
                        f"request_id={request_id} 已用于 {row['operation']}，"
                        f"当前请求为 {operation} 或参数不同"
                    )
                stored = json.loads(row["response"])
                stored["replayed"] = True
                stored["idempotent_status"] = row["status"]
                return stored

            try:
                result = fn(c)
            except ServiceError as failure:
                # 失败也占用 request_id：换侧重放同样失败，换参仍被拒绝
                c.execute(
                    "INSERT INTO idempotency_requests (request_id,operation,"
                    "fingerprint,status,response,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        request_id,
                        operation,
                        fingerprint,
                        "failed",
                        json.dumps(failure.to_dict(), sort_keys=True),
                        self.clock.now(),
                    ),
                )
                raise
            c.execute(
                "INSERT INTO idempotency_requests (request_id,operation,"
                "fingerprint,status,response,created_at) VALUES (?,?,?,?,?,?)",
                (
                    request_id,
                    operation,
                    fingerprint,
                    "completed",
                    json.dumps(result, sort_keys=True),
                    self.clock.now(),
                ),
            )

        # 事务已持久化；after_commit 崩溃模拟"客户端没收到响应"
        self.crash.hook(f"{operation}.after_commit")
        result["replayed"] = False
        result["idempotent_status"] = "completed"
        return result

    def _require_enabled(self, c: sqlite3.Connection, account_id: str) -> sqlite3.Row:
        row = c.execute(
            "SELECT * FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if row is None:
            raise AccountNotFound(f"账号不存在: {account_id}")
        if not row["enabled"]:
            raise AccountDisabled(f"账号已禁用: {account_id}")
        return row

    def _require_session(
        self,
        c: sqlite3.Connection,
        account_id: str,
        session_token: str,
        *,
        fresh: bool = True,
    ) -> sqlite3.Row:
        """校验浏览器会话：存在、未撤销、未过期、属于该账号，且登录仍新鲜。"""
        row = c.execute(
            "SELECT * FROM login_sessions WHERE token=?", (session_token,)
        ).fetchone()
        if row is None or row["revoked"]:
            raise SessionNotFound("会话不存在或已被撤销")
        now = self.clock.now()
        if now >= row["expires_at"]:
            raise SessionExpired("浏览器会话已过期")
        if row["account_id"] != account_id:
            # 不向调用方透露其他账号的会话信息
            raise SessionNotFound("会话不属于该内部账号")
        if fresh and now - row["last_login_at"] > self.login_freshness:
            raise LoginNotRecent(
                f"最近一次登录在 {now - row['last_login_at']} 秒前，"
                f"超过新鲜窗口 {self.login_freshness} 秒"
            )
        return row

    def _count_login_methods(self, c: sqlite3.Connection, account_id: str) -> int:
        n = c.execute(
            "SELECT COUNT(*) FROM external_identities WHERE account_id=? AND active=1",
            (account_id,),
        ).fetchone()[0]
        has_password = c.execute(
            "SELECT password_ref IS NOT NULL FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()[0]
        return n + (1 if has_password else 0)

    # ------------------------------------------------------------- 账号/登录
    def create_account(
        self,
        request_id: str,
        account_id: str,
        display_name: str,
        password: str | None = None,
    ) -> dict:
        salt = self.rng.randbytes(16)
        password_ref = hash_password(password, salt) if password is not None else None
        params = {
            "account_id": account_id,
            "display_name": display_name,
            "has_password": password is not None,
        }

        def work(c: sqlite3.Connection) -> dict:
            now = self.clock.now()
            try:
                c.execute(
                    "INSERT INTO accounts (account_id,display_name,password_ref,"
                    "enabled,created_at) VALUES (?,?,?,1,?)",
                    (account_id, display_name, password_ref, now),
                )
            except sqlite3.IntegrityError as exc:
                raise AccountAlreadyExists(f"账号已存在: {account_id}") from exc
            self._audit(
                c,
                "account_created",
                account_id=account_id,
                request_id=request_id,
                detail={"display_name": display_name, "has_password": password is not None},
            )
            self.crash.hook("create_account.before_commit")
            return {
                "account_id": account_id,
                "display_name": display_name,
                "enabled": True,
                "created_at": now,
            }

        return self._idempotent(request_id, "create_account", params, work)

    def login(self, request_id: str, account_id: str, password: str) -> dict:
        params = {"account_id": account_id, "password": password}

        def work(c: sqlite3.Connection) -> dict:
            account = self._require_enabled(c, account_id)
            stored = account["password_ref"]
            if stored is None or not verify_password(password, stored):
                raise PasswordMismatch("口令校验失败（账号可能未设置本地口令）")
            now = self.clock.now()
            token = self._id("sess", 24)
            c.execute(
                "INSERT INTO login_sessions (token,account_id,created_at,"
                "last_login_at,expires_at,revoked) VALUES (?,?,?,?,?,0)",
                (token, account_id, now, now, now + self.session_ttl),
            )
            self._audit(
                c,
                "login",
                account_id=account_id,
                request_id=request_id,
                detail={"session_ttl": self.session_ttl},
            )
            self.crash.hook("login.before_commit")
            return {
                "account_id": account_id,
                "session_token": token,
                "last_login_at": now,
                "expires_at": now + self.session_ttl,
            }

        return self._idempotent(request_id, "login", params, work)

    # ----------------------------------------------------------------- 挑战
    def start_challenge(
        self, request_id: str, account_id: str, session_token: str, issuer: str
    ) -> dict:
        params = {
            "account_id": account_id,
            "session_token": session_token,
            "issuer": issuer,
        }

        def work(c: sqlite3.Connection) -> dict:
            self._require_enabled(c, account_id)
            self._require_session(c, account_id, session_token, fresh=True)
            if not self.key_store.knows(issuer):
                raise UnknownIssuerError(f"未登记的身份源: {issuer}")
            now = self.clock.now()
            challenge_id = self._id("chl", 14)
            nonce = b64url_encode(self.rng.randbytes(18))
            expires_at = now + self.challenge_ttl
            c.execute(
                "INSERT INTO challenges (challenge_id,account_id,issuer,"
                "session_token,nonce,status,created_at,expires_at) "
                "VALUES (?,?,?,?,?,'pending',?,?)",
                (challenge_id, account_id, issuer, session_token, nonce, now, expires_at),
            )
            self._audit(
                c,
                "challenge_started",
                account_id=account_id,
                request_id=request_id,
                issuer=issuer,
                challenge_id=challenge_id,
                detail={"nonce": nonce, "expires_at": expires_at},
            )
            self.crash.hook("start_challenge.before_commit")
            return {
                "challenge_id": challenge_id,
                "account_id": account_id,
                "issuer": issuer,
                "nonce": nonce,
                "status": "pending",
                "created_at": now,
                "expires_at": expires_at,
            }

        return self._idempotent(request_id, "start_challenge", params, work)

    def complete_challenge(
        self, request_id: str, challenge_id: str, session_token: str, assertion_token: str
    ) -> dict:
        # 断言原文纳入幂等指纹：同一 request_id 换断言必须拒绝
        params = {
            "challenge_id": challenge_id,
            "session_token": session_token,
            "assertion": assertion_token,
        }

        def work(c: sqlite3.Connection) -> dict:
            now = self.clock.now()
            ch = c.execute(
                "SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
            if ch is None:
                raise ChallengeNotFound(f"挑战不存在: {challenge_id}")
            if ch["status"] == "consumed":
                raise ChallengeConsumed("挑战已被消费，禁止重放")
            if ch["status"] == "revoked":
                raise ChallengeRevoked("挑战已随账号禁用被撤销")
            if now >= ch["expires_at"]:
                # 惰性落状态，便于审计观察
                c.execute(
                    "UPDATE challenges SET status='expired' WHERE challenge_id=?",
                    (challenge_id,),
                )
                raise ChallengeExpired("挑战已过期")

            # 双向证明之一：内部账号近期登录 + 会话与挑战绑定一致
            self._require_enabled(c, ch["account_id"])
            self._require_session(c, ch["account_id"], session_token, fresh=True)
            if session_token != ch["session_token"]:
                raise ChallengeSessionMismatch(
                    "当前浏览器会话与挑战绑定的会话不同，禁止交换会话完成绑定"
                )

            # 双向证明之二：外部身份所有权——独立验签 HMAC 断言
            try:
                secret = self.key_store.secret_of(ch["issuer"])
            except KeyError as exc:
                raise AssertionBadSignature("身份源密钥不可用") from exc
            payload = verify_assertion_signature(assertion_token, secret)
            if payload.get("iss") != ch["issuer"]:
                raise ChallengeIssuerMismatch(
                    f"断言 issuer={payload.get('iss')!r} 与挑战目标 "
                    f"{ch['issuer']!r} 不一致"
                )
            if payload.get("aud") != self.audience:
                raise AssertionAudienceMismatch("断言受众不匹配")
            if now >= int(payload["exp"]):
                raise AssertionExpired("断言已过期")
            if now < int(payload["nbf"]):
                raise AssertionNotYetValid("断言尚未生效")
            if payload.get("nonce") != ch["nonce"]:
                raise AssertionNonceMismatch("断言 nonce 与挑战不一致，疑似重放")
            subject = str(payload["sub"])
            email = str(payload.get("email", ""))

            # 显式预检 + 唯一索引兜底：跨进程抢绑只有一个胜者
            existing = c.execute(
                "SELECT account_id FROM external_identities "
                "WHERE issuer=? AND subject=? AND active=1",
                (ch["issuer"], subject),
            ).fetchone()
            if existing is not None:
                raise IdentityAlreadyBound(
                    f"外部身份 {ch['issuer']}/{subject} 已绑定账号 "
                    f"{existing['account_id']}"
                )

            link_id = self._id("link", 14)
            try:
                c.execute(
                    "INSERT INTO external_identities (link_id,account_id,issuer,"
                    "subject,email,created_at,active) VALUES (?,?,?,?,?,?,1)",
                    (link_id, ch["account_id"], ch["issuer"], subject, email, now),
                )
            except sqlite3.IntegrityError as exc:
                raise IdentityAlreadyBound(
                    f"外部身份 {ch['issuer']}/{subject} 已被其他进程抢先绑定"
                ) from exc
            c.execute(
                "UPDATE challenges SET status='consumed', consumed_at=?, link_id=? "
                "WHERE challenge_id=?",
                (now, link_id, challenge_id),
            )
            self._audit(
                c,
                "identity_linked",
                account_id=ch["account_id"],
                request_id=request_id,
                issuer=ch["issuer"],
                subject=subject,
                challenge_id=challenge_id,
                detail={"link_id": link_id, "email": email},
            )
            self.crash.hook("complete_challenge.before_commit")
            return {
                "link_id": link_id,
                "account_id": ch["account_id"],
                "issuer": ch["issuer"],
                "subject": subject,
                "email": email,
                "challenge_id": challenge_id,
                "status": "linked",
                "linked_at": now,
            }

        return self._idempotent(request_id, "complete_challenge", params, work)

    # ----------------------------------------------------------------- 解绑
    def unlink(self, request_id: str, link_id: str, session_token: str) -> dict:
        params = {"link_id": link_id, "session_token": session_token}

        def work(c: sqlite3.Connection) -> dict:
            link = c.execute(
                "SELECT * FROM external_identities WHERE link_id=?", (link_id,)
            ).fetchone()
            if link is None or not link["active"]:
                raise IdentityNotLinked(f"绑定不存在或已解除: {link_id}")
            account_id = link["account_id"]
            self._require_enabled(c, account_id)
            self._require_session(c, account_id, session_token, fresh=True)

            methods = self._count_login_methods(c, account_id)
            if methods <= 1:
                raise LastLoginMethod(
                    "解绑后该账号将没有任何可用登录方式，操作被拒绝"
                )
            now = self.clock.now()
            c.execute(
                "UPDATE external_identities SET active=0, revoked_at=? WHERE link_id=?",
                (now, link_id),
            )
            self._audit(
                c,
                "identity_unlinked",
                account_id=account_id,
                request_id=request_id,
                issuer=link["issuer"],
                subject=link["subject"],
                detail={"link_id": link_id},
            )
            self.crash.hook("unlink.before_commit")
            return {
                "link_id": link_id,
                "account_id": account_id,
                "issuer": link["issuer"],
                "subject": link["subject"],
                "status": "unlinked",
                "unlinked_at": now,
            }

        return self._idempotent(request_id, "unlink", params, work)

    # ------------------------------------------------------------- 禁用/启用
    def disable_account(self, request_id: str, account_id: str, session_token: str) -> dict:
        params = {"account_id": account_id, "session_token": session_token}

        def work(c: sqlite3.Connection) -> dict:
            self._require_enabled(c, account_id)
            self._require_session(c, account_id, session_token, fresh=True)
            now = self.clock.now()
            c.execute(
                "UPDATE accounts SET enabled=0, disabled_at=? WHERE account_id=?",
                (now, account_id),
            )
            # 撤销全部会话：禁用提交后不可能再有新操作成功
            c.execute(
                "UPDATE login_sessions SET revoked=1 WHERE account_id=? AND revoked=0",
                (account_id,),
            )
            # 撤销全部待处理挑战：重新启用也不会复活
            c.execute(
                "UPDATE challenges SET status='revoked' "
                "WHERE account_id=? AND status='pending'",
                (account_id,),
            )
            revoked_challenges = c.execute(
                "SELECT COUNT(*) FROM challenges WHERE account_id=? AND status='revoked'",
                (account_id,),
            ).fetchone()[0]
            self._audit(
                c,
                "account_disabled",
                account_id=account_id,
                request_id=request_id,
                detail={"revoked_challenges": revoked_challenges},
            )
            self.crash.hook("disable_account.before_commit")
            return {
                "account_id": account_id,
                "enabled": False,
                "disabled_at": now,
                "revoked_challenges": revoked_challenges,
            }

        return self._idempotent(request_id, "disable_account", params, work)

    def remove_local_password(self, account_id: str) -> dict:
        """管理动作：移除本地口令引用，把账号转成纯联邦登录账号。

        用于构造"仅剩外部身份"的测试前提；要求账号当前至少有一个活跃外部
        身份，否则移除后将没有任何登录方式，直接拒绝。
        """
        with transaction(self.conn) as c:
            row = c.execute(
                "SELECT password_ref FROM accounts WHERE account_id=?", (account_id,)
            ).fetchone()
            if row is None:
                raise AccountNotFound(f"账号不存在: {account_id}")
            n = c.execute(
                "SELECT COUNT(*) FROM external_identities WHERE account_id=? AND active=1",
                (account_id,),
            ).fetchone()[0]
            if n == 0:
                raise LastLoginMethod("账号没有任何外部身份，移除口令将失去全部登录方式")
            c.execute(
                "UPDATE accounts SET password_ref=NULL WHERE account_id=?", (account_id,)
            )
            self._audit(
                c,
                "local_password_removed",
                account_id=account_id,
                detail={"external_identities": n},
            )
        return {"account_id": account_id, "password_ref": None,
                "external_identities": n}

    def enable_account(self, request_id: str, account_id: str) -> dict:
        """重新启用。管理动作：不恢复旧会话、不恢复旧挑战。"""
        params = {"account_id": account_id}

        def work(c: sqlite3.Connection) -> dict:
            row = c.execute(
                "SELECT enabled FROM accounts WHERE account_id=?", (account_id,)
            ).fetchone()
            if row is None:
                raise AccountNotFound(f"账号不存在: {account_id}")
            now = self.clock.now()
            c.execute(
                "UPDATE accounts SET enabled=1, disabled_at=NULL WHERE account_id=?",
                (account_id,),
            )
            self._audit(
                c,
                "account_enabled",
                account_id=account_id,
                request_id=request_id,
                detail={"note": "旧会话与旧挑战保持撤销状态，不会自动恢复"},
            )
            self.crash.hook("enable_account.before_commit")
            return {"account_id": account_id, "enabled": True, "enabled_at": now}

        return self._idempotent(request_id, "enable_account", params, work)

    # ----------------------------------------------------------------- 只读
    def get_account(self, account_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT account_id,display_name,enabled,created_at,disabled_at "
            "FROM accounts WHERE account_id=?",
            (account_id,),
        ).fetchone()
        return dict(row) if row else None

    def find_active_identity(self, issuer: str, subject: str) -> dict | None:
        row = self.conn.execute(
            "SELECT link_id,account_id,issuer,subject,email,created_at,active "
            "FROM external_identities WHERE issuer=? AND subject=? AND active=1",
            (issuer, subject),
        ).fetchone()
        return dict(row) if row else None

    def list_identities(self, account_id: str, *, active_only: bool = True) -> list[dict]:
        sql = (
            "SELECT link_id,account_id,issuer,subject,email,created_at,active,"
            "revoked_at FROM external_identities WHERE account_id=?"
        )
        if active_only:
            sql += " AND active=1"
        sql += " ORDER BY created_at, link_id"
        return [dict(r) for r in self.conn.execute(sql, (account_id,)).fetchall()]

    def list_challenges(self, account_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT challenge_id,account_id,issuer,session_token,nonce,status,"
            "created_at,expires_at,consumed_at,link_id FROM challenges "
            "WHERE account_id=? ORDER BY created_at",
            (account_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_audit(
        self,
        *,
        account_id: str | None = None,
        request_id: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        sql = (
            "SELECT event_id,event_type,account_id,request_id,issuer,subject,"
            "challenge_id,detail,created_at FROM audit_events WHERE 1=1"
        )
        args: list = []
        if account_id:
            sql += " AND account_id=?"
            args.append(account_id)
        if request_id:
            sql += " AND request_id=?"
            args.append(request_id)
        if event_type:
            sql += " AND event_type=?"
            args.append(event_type)
        sql += " ORDER BY created_at, event_id"
        out = []
        for r in self.conn.execute(sql, args).fetchall():
            item = dict(r)
            item["detail"] = json.loads(item["detail"])
            out.append(item)
        return out
