"""crypto / idp 单元测试：HMAC 断言结构、恒时验签、篡改检测、密钥库与模拟 IdP。"""

from __future__ import annotations

import json
import os
import unittest

from solution.clock import FakeClock
from solution.crypto import (
    b64url_decode,
    b64url_encode,
    canonical_hash,
    canonical_bytes,
    parse_assertion,
    sign_assertion,
    verify_assertion_signature,
    verify_password,
    hash_password,
)
from solution.errors import AssertionBadSignature
from solution.idp import IdentityClaim, IssuerKeyStore, MockIdentityProvider, UnknownIssuer
from tests._helpers import AUDIENCE, ISSUER_A, build_key_store, seeded_rng


class Base64UrlTest(unittest.TestCase):
    def test_roundtrip_without_padding(self):
        for n in range(0, 40):
            raw = bytes((i * 7 + n) % 256 for i in range(n))
            text = b64url_encode(raw)
            self.assertNotIn("=", text)
            self.assertEqual(b64url_decode(text), raw)

    def test_decode_rejects_garbage(self):
        with self.assertRaises(AssertionBadSignature):
            b64url_decode("@@@not-base64@@@")


class HmacAssertionTest(unittest.TestCase):
    def setUp(self):
        self.secret = b"unit-test-secret-0123456789abcdef"
        self.payload = {
            "iss": ISSUER_A, "sub": "sub-x", "email": "x@example.com",
            "aud": AUDIENCE, "nonce": "nonce-1", "iat": 100, "nbf": 100,
            "exp": 200, "jti": "jti-1",
        }

    def test_sign_and_verify_roundtrip(self):
        token = sign_assertion(self.payload, self.secret)
        self.assertEqual(len(token.split(".")), 3)
        got = verify_assertion_signature(token, self.secret)
        self.assertEqual(got, self.payload)

    def test_wrong_secret_rejected_constant_time(self):
        token = sign_assertion(self.payload, self.secret)
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(token, b"another-secret-abcdef0123456789")

    def test_tampered_payload_rejected(self):
        token = sign_assertion(self.payload, self.secret)
        head, body, sig = token.split(".")
        tampered = self.payload | {"sub": "sub-attacker"}
        evil_body = b64url_encode(canonical_bytes(tampered))
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(".".join([head, evil_body, sig]), self.secret)

    def test_corrupt_signature_rejected(self):
        token = sign_assertion(self.payload, self.secret)
        head, body, _sig = token.split(".")
        evil = head + "." + body + "." + b64url_encode(b"\x00" * 32)
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(evil, self.secret)

    def test_malformed_structure_rejected(self):
        for bad in ("only-one-part", "a.b", "a.b.c.d", ""):
            with self.assertRaises(AssertionBadSignature):
                verify_assertion_signature(bad, self.secret)

    def test_unsupported_header_rejected(self):
        token = sign_assertion(self.payload, self.secret)
        _head, body, sig = token.split(".")
        evil_head = b64url_encode(canonical_bytes({"alg": "none", "typ": "local-assertion"}))
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(".".join([evil_head, body, sig]), self.secret)

    def test_parse_returns_structured_parts(self):
        token = sign_assertion(self.payload, self.secret)
        header, payload, signature, signing_input = parse_assertion(token)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(payload["sub"], "sub-x")
        self.assertEqual(len(signature), 32)
        self.assertIn(".", signing_input.decode())


class CanonicalHashTest(unittest.TestCase):
    def test_key_order_independent(self):
        a = {"a": 1, "b": [1, 2, {"c": 3}]}
        b = {"b": [1, 2, {"c": 3}], "a": 1}
        self.assertEqual(canonical_hash(a), canonical_hash(b))

    def test_distinct_inputs_distinct_hash(self):
        self.assertNotEqual(canonical_hash({"x": 1}), canonical_hash({"x": 2}))


class PasswordHashTest(unittest.TestCase):
    def test_pbkdf2_roundtrip_and_wrong_password(self):
        stored = hash_password("correct horse", salt=b"\x01" * 16)
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("correct horse", stored))
        self.assertFalse(verify_password("wrong horse", stored))

    def test_malformed_stored_value_returns_false(self):
        self.assertFalse(verify_password("x", "not-a-valid-ref"))
        self.assertFalse(verify_password("x", "unknown$1$2$3"))


class KeyStoreAndIdpTest(unittest.TestCase):
    def setUp(self):
        self.store = build_key_store()
        self.clock = FakeClock(1_700_000_000)
        self.rng = seeded_rng(99)
        self.idp = MockIdentityProvider(ISSUER_A, self.store, self.clock, rng=self.rng)

    def test_keystore_unknown_issuer(self):
        with self.assertRaises(UnknownIssuer):
            self.store.secret_of("https://unknown.example/")
        self.assertFalse(self.store.knows("https://unknown.example/"))

    def test_idp_requires_registered_issuer(self):
        with self.assertRaises(UnknownIssuer):
            MockIdentityProvider("https://unknown.example/", self.store, self.clock)

    def test_issued_token_verifies_with_registered_secret(self):
        pack = self.idp.issue(
            IdentityClaim(ISSUER_A, "sub-1", "a@example.com"), AUDIENCE, "nonce-9"
        )
        payload = verify_assertion_signature(
            pack["token"], self.store.secret_of(ISSUER_A)
        )
        self.assertEqual(payload["iss"], ISSUER_A)
        self.assertEqual(payload["sub"], "sub-1")
        self.assertEqual(payload["aud"], AUDIENCE)
        self.assertEqual(payload["nonce"], "nonce-9")

    def test_wrong_key_signature_fails_verification(self):
        pack = self.idp.issue(
            IdentityClaim(ISSUER_A, "sub-1", "a@example.com"),
            AUDIENCE, "n", sign_with_wrong_key=True,
        )
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(pack["token"], self.store.secret_of(ISSUER_A))

    def test_corrupt_signature_flag(self):
        pack = self.idp.issue(
            IdentityClaim(ISSUER_A, "sub-1", "a@example.com"),
            AUDIENCE, "n", corrupt_signature=True,
        )
        with self.assertRaises(AssertionBadSignature):
            verify_assertion_signature(pack["token"], self.store.secret_of(ISSUER_A))

    def test_backdate_and_future_nbf_claims(self):
        expired = self.idp.issue(
            IdentityClaim(ISSUER_A, "s", "e"), AUDIENCE, "n", backdate_expired=True
        )["payload"]
        self.assertLess(expired["exp"], self.clock.now())
        future = self.idp.issue(
            IdentityClaim(ISSUER_A, "s", "e"), AUDIENCE, "n", future_nbf=True
        )["payload"]
        self.assertGreater(future["nbf"], self.clock.now())

    def test_keystore_json_roundtrip(self):
        path = os.path.join(os.path.dirname(__file__), "..", ".runtime-tmp", "ks.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.store.to_json_file(path)
        reloaded = IssuerKeyStore.from_json_file(path)
        self.assertEqual(reloaded.issuers(), self.store.issuers())
        for issuer in self.store.issuers():
            self.assertEqual(reloaded.secret_of(issuer), self.store.secret_of(issuer))


if __name__ == "__main__":
    unittest.main()
