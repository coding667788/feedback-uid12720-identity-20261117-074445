"""SQLite 持久层。

并发模型（关键）：
- WAL 模式允许一个写事务与多个读事务共存；所有写事务在库级别串行执行，
  写事务的提交顺序就是本题要求的"线性化顺序"。
- 每个事务都以 ``BEGIN IMMEDIATE`` 开启：一旦开启即拿到写锁，配合
  ``busy_timeout`` 让第二个进程阻塞等待而不是立即报 SQLITE_BUSY。
- 连接使用 autocommit 模式（isolation_level=None），事务边界完全由本模块
  的 :func:`transaction` 显式控制，杜绝驱动隐式 BEGIN 干扰崩溃点语义。

唯一性保证：
- external_identities 对 (issuer, subject) 建 *部分唯一索引*
  （仅 active=1 行），两个进程同时抢绑同一外部身份时，数据库只允许一个
  事务提交，另一个在 COMMIT/写冲突时失败——这是跨进程一致性的最终防线，
  不依赖任何进程内锁。
- idempotency_requests 以 request_id 为主键，保证幂等记录自身唯一。
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=10000;

CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    password_ref TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    disabled_at  INTEGER
);

CREATE TABLE IF NOT EXISTS login_sessions (
    token        TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    created_at   INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON login_sessions(account_id);

-- 外部身份唯一键是 (issuer, subject)；email 仅展示、不建唯一约束。
-- 部分唯一索引：解绑（active=0）后允许重新绑定，活跃绑定全局唯一。
CREATE TABLE IF NOT EXISTS external_identities (
    link_id      TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1,
    revoked_at   INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_issuer_subject
    ON external_identities(issuer, subject) WHERE active = 1;
CREATE INDEX IF NOT EXISTS idx_identity_account
    ON external_identities(account_id);

-- 挑战绑定：内部账号 + 目标 issuer + 浏览器会话 + 到期时间 + 一次性 nonce
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(account_id),
    issuer       TEXT NOT NULL,
    session_token TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('pending','consumed','expired','revoked')),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    consumed_at  INTEGER,
    link_id      TEXT
);
CREATE INDEX IF NOT EXISTS idx_challenge_account ON challenges(account_id);

-- 幂等表：request_id 全局唯一；fingerprint 记录首次参数指纹
CREATE TABLE IF NOT EXISTS idempotency_requests (
    request_id   TEXT PRIMARY KEY,
    operation    TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('completed','failed')),
    response     TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

-- 审计事件与业务写在同一事务内提交
CREATE TABLE IF NOT EXISTS audit_events (
    event_id     TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    account_id   TEXT,
    request_id   TEXT,
    issuer       TEXT,
    subject      TEXT,
    challenge_id TEXT,
    detail       TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_events(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_events(request_id);
"""


def connect(db_path: str, *, busy_timeout_ms: int = 10_000) -> sqlite3.Connection:
    """打开一个进程内独立连接（每个进程各自 connect，禁止跨进程共享）。"""
    conn = sqlite3.connect(
        db_path,
        isolation_level=None,  # autocommit：事务由本模块显式管理
        timeout=busy_timeout_ms / 1000.0,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    conn.execute("PRAGMA foreign_keys=ON")
    # WAL 只需设置一次，重复执行也无副作用
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def initialize_database(db_path: str) -> None:
    """建库建表（幂等）。"""
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """显式 ``BEGIN IMMEDIATE`` 事务上下文。

    进入即获取保留锁/写锁，使并发进程在 busy_timeout 内排队，按获取锁的
    顺序串行提交。正常退出 COMMIT，异常退出 ROLLBACK。
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
