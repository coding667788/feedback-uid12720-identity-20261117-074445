"""模拟身份提供方（IdP）与密钥库。

不接任何真实账号：IdP 只是一个本地组件，持有 (issuer -> HMAC 共享密钥)，
按本题协议签发"外部身份所有权断言"。验证方（service）只信任密钥库里
登记过的 issuer，并独立验签——因此可以模拟"签名被篡改""未知 issuer"
"aud 被调包"等攻击用例。

断言 payload 字段：
    iss  : 身份源标识，如 https://idp-alpha.example/
    sub  : 该身份源内的外部主体唯一标识
    email: 展示用邮箱（明确不参与账号合并判定）
    aud  : 受众，必须等于本服务 DEFAULT_AUDIENCE
    nonce: 挑战随机数，把断言与一次性挑战绑定，防止重放
    iat  : 签发时间（Unix 秒）
    nbf  : 生效时间
    exp  : 过期时间
    jti  : 断言唯一 id（审计/重放追踪用）
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterable

from .clock import Clock, FakeClock
from .crypto import b64url_encode, sign_assertion

# 断言默认有效期（秒）
DEFAULT_ASSERTION_TTL = 120


class UnknownIssuer(KeyError):
    """密钥库中不存在该 issuer。"""


class IssuerKeyStore:
    """issuer -> HMAC 密钥的本地密钥库（JSON 文件支持）。"""

    def __init__(self, keys: dict[str, bytes] | None = None):
        self._keys: dict[str, bytes] = dict(keys or {})

    @classmethod
    def from_json_file(cls, path: str) -> "IssuerKeyStore":
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        keys = {item["issuer"]: bytes.fromhex(item["secret_hex"]) for item in raw}
        return cls(keys)

    def to_json_file(self, path: str) -> None:
        raw = [
            {"issuer": issuer, "secret_hex": secret.hex()}
            for issuer, secret in sorted(self._keys.items())
        ]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False, indent=2)

    def issuers(self) -> list[str]:
        return sorted(self._keys)

    def secret_of(self, issuer: str) -> bytes:
        try:
            return self._keys[issuer]
        except KeyError as exc:
            raise UnknownIssuer(issuer) from exc

    def knows(self, issuer: str) -> bool:
        return issuer in self._keys


@dataclass
class IdentityClaim:
    """一个外部身份的可签发信息（sub 才是身份键，email 仅展示）。"""

    issuer: str
    subject: str
    email: str


class MockIdentityProvider:
    """本地模拟 IdP：用共享密钥为外部身份签发 HMAC 断言。"""

    def __init__(
        self,
        issuer: str,
        key_store: IssuerKeyStore,
        clock: Clock,
        *,
        ttl_seconds: int = DEFAULT_ASSERTION_TTL,
        rng=None,
    ):
        if not key_store.knows(issuer):
            raise UnknownIssuer(issuer)
        self.issuer = issuer
        self.key_store = key_store
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self._rng = rng

    def issue(
        self,
        claim: IdentityClaim,
        audience: str,
        nonce: str,
        *,
        ttl_seconds: int | None = None,
        issuer_override: str | None = None,
        audience_override: str | None = None,
        sign_with_wrong_key: bool = False,
        corrupt_signature: bool = False,
        backdate_expired: bool = False,
        future_nbf: bool = False,
    ) -> dict:
        """签发断言，返回 {token, payload}。

        带 *_override / corrupt_* 参数的分支专门用于构造攻击/异常用例：
        内容可以被调包，但密钥仍只有正确 issuer 持有，因此验签必然失败。
        """
        if claim.issuer != self.issuer:
            raise ValueError("claim.issuer 与本 IdP 的 issuer 不一致")
        now = self.clock.now()
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        payload = {
            "iss": issuer_override or claim.issuer,
            "sub": claim.subject,
            "email": claim.email,
            "aud": audience_override or audience,
            "nonce": nonce,
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": b64url_encode(self._random(16)),
        }
        if backdate_expired:
            payload["iat"] = now - ttl - 1
            payload["nbf"] = now - ttl - 1
            payload["exp"] = now - 1
        if future_nbf:
            payload["nbf"] = now + ttl
            payload["exp"] = now + 2 * ttl

        signing_issuer = self.issuer
        secret = self.key_store.secret_of(signing_issuer)
        if sign_with_wrong_key:
            # 用一把确定性的"外来密钥"签名，模拟身份源之外的攻击者伪造
            secret = b"attacker-key-" + os.urandom(0) + b"0123456789abcdef"
        token = sign_assertion(payload, secret)
        if corrupt_signature:
            head, body, _sig = token.split(".")
            token = head + "." + body + "." + b64url_encode(b"\x00" * 32)
        return {"token": token, "payload": payload}

    def _random(self, n: int) -> bytes:
        if self._rng is not None:
            return self._rng.randbytes(n)
        return os.urandom(n)


def build_idps(
    key_store: IssuerKeyStore, clock: Clock, *, rng=None
) -> dict[str, MockIdentityProvider]:
    """为密钥库中每个 issuer 构造一个模拟 IdP。"""
    return {
        issuer: MockIdentityProvider(issuer, key_store, clock, rng=rng)
        for issuer in key_store.issuers()
    }
