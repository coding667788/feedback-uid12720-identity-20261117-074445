"""测试共享夹具：临时目录、固定密钥库、种子 RNG、假时钟、服务装配助手。

所有测试只在 tempfile 临时目录（位于项目 .runtime-tmp 下）与本机模拟组件内
活动，固定种子 20261117，可重复执行。
"""

from __future__ import annotations

import os
import random
import tempfile

from solution.clock import FakeClock
from solution.idp import IdentityClaim, IssuerKeyStore, MockIdentityProvider
from solution.service import LinkingService

SEED = 20261117
CLOCK_START = 1_700_000_000
ISSUER_A = "https://idp-alpha.example/"
ISSUER_B = "https://idp-bravo.example/"
AUDIENCE = "local-linking-service"

_RUNTIME_TMP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".runtime-tmp"
)


def new_temp_dir() -> str:
    os.makedirs(_RUNTIME_TMP, exist_ok=True)
    return tempfile.mkdtemp(prefix="unittest-", dir=_RUNTIME_TMP)


def seeded_rng(index: int = 0) -> random.Random:
    return random.Random(SEED * 1_000_003 + index)


def build_key_store() -> IssuerKeyStore:
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "samples",
        "issuer_keys.json",
    )
    return IssuerKeyStore.from_json_file(path)


def build_service(
    db_path: str,
    *,
    rng_index: int = 0,
    clock: FakeClock | None = None,
    crash_plan: dict | None = None,
    key_store: IssuerKeyStore | None = None,
) -> LinkingService:
    return LinkingService(
        db_path,
        key_store or build_key_store(),
        clock or FakeClock(CLOCK_START),
        audience=AUDIENCE,
        rng=seeded_rng(rng_index),
        crash_plan=crash_plan,
    )


def mint_token(
    key_store: IssuerKeyStore,
    clock: FakeClock,
    rng: random.Random,
    issuer: str,
    subject: str,
    nonce: str,
    *,
    email: str = "user@example.com",
    **issue_kwargs,
) -> str:
    idp = MockIdentityProvider(issuer, key_store, clock, rng=rng)
    pack = idp.issue(
        IdentityClaim(issuer, subject, email), AUDIENCE, nonce, **issue_kwargs
    )
    return pack["token"]


def full_link(
    service: LinkingService,
    request_prefix: str,
    account_id: str,
    session: str,
    issuer: str,
    subject: str,
    *,
    email: str = "user@example.com",
) -> dict:
    """完整走一遍 start_challenge -> mint -> complete，返回绑定结果。"""
    ch = service.start_challenge(
        f"{request_prefix}-ch", account_id, session, issuer
    )
    token = mint_token(
        service.key_store,
        service.clock,
        service.rng,
        issuer,
        subject,
        ch["nonce"],
        email=email,
    )
    return service.complete_challenge(
        f"{request_prefix}-link", ch["challenge_id"], session, token
    )
