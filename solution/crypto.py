"""密码学原语（仅标准库：hmac / hashlib / base64 / json）。

本项目的"联合身份断言"是本题自定义的紧凑令牌，结构与 JWT 相似但不依赖
第三方库：

    base64url(canonical(header)) . base64url(canonical(payload)) . base64url(sig)

- header  固定为 {"alg": "HS256", "typ": "local-assertion"}
- payload 为身份源对外部身份的所有权断言（iss/sub/email/aud/nonce/iat/nbf/exp/jti）
- sig = HMAC-SHA256(issuer 共享密钥, 前两段拼接字节)，比较使用 hmac.compare_digest

时间类声明（exp/nbf）的判定放在 service 层，以便注入 FakeClock；
本模块只负责结构、签名与恒时校验。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from .errors import AssertionBadSignature

HEADER = {"alg": "HS256", "typ": "local-assertion"}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """容忍省略填充的 base64url；输入非法时抛 AssertionBadSignature。"""
    try:
        padding = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise AssertionBadSignature(f"base64url 解码失败: {exc}") from exc


def canonical_bytes(obj: dict) -> bytes:
    """规范 JSON：键排序、无多余空白、保留 Unicode。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: dict) -> str:
    """对 JSON 可序列化对象做规范哈希（幂等键指纹、审计指纹使用）。"""
    return sha256_hex(canonical_bytes(obj))


def hmac_sha256(secret: bytes, message: bytes) -> bytes:
    return hmac.new(secret, message, hashlib.sha256).digest()


def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def sign_assertion(payload: dict, secret: bytes) -> str:
    """用 issuer 共享密钥对断言 payload 签名，返回紧凑令牌字符串。"""
    signing_input = (
        b64url_encode(canonical_bytes(HEADER))
        + "."
        + b64url_encode(canonical_bytes(payload))
    )
    signature = hmac_sha256(secret, signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(signature)


def parse_assertion(token: str) -> tuple[dict, dict, bytes]:
    """解析令牌结构，返回 (header, payload, signing_input)；不校验签名。"""
    parts = token.split(".")
    if len(parts) != 3:
        raise AssertionBadSignature("断言必须由 header.payload.signature 三段组成")
    header_b, payload_b, sig_b = parts
    try:
        header = json.loads(b64url_decode(header_b))
        payload = json.loads(b64url_decode(payload_b))
        signature = b64url_decode(sig_b)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AssertionBadSignature(f"断言内容无法解析: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise AssertionBadSignature("断言 header/payload 必须是 JSON 对象")
    signing_input = (header_b + "." + payload_b).encode("ascii")
    return header, payload, signature, signing_input


def verify_assertion_signature(token: str, secret: bytes) -> dict:
    """验签并返回 payload。结构损坏或签名不符一律抛 AssertionBadSignature。"""
    header, payload, signature, signing_input = parse_assertion(token)
    if header.get("alg") != "HS256" or header.get("typ") != "local-assertion":
        raise AssertionBadSignature("不支持的断言头")
    expected = hmac_sha256(secret, signing_input)
    if not constant_time_equals(expected, signature):
        raise AssertionBadSignature("HMAC 签名不匹配")
    return payload


def hash_password(password: str, salt: bytes, iterations: int = 200_000) -> str:
    """本地口令使用 PBKDF2-HMAC-SHA256 存储（标准库 hashlib）。"""
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return f"pbkdf2_sha256${iterations}${b64url_encode(salt)}${b64url_encode(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iter_text, salt_b64, digest_b64 = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_text)
        salt = b64url_decode(salt_b64)
        expected = b64url_decode(digest_b64)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return constant_time_equals(candidate, expected)
