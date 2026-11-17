"""统一错误码与异常层次。

所有业务失败都抛出 :class:`ServiceError` 的子类，携带稳定的字符串错误码
``code``。CLI / runner 把错误码原样写入结果，供用例断言。
"""


class ServiceError(Exception):
    """业务异常基类。code 为稳定错误码，http_status 仅作语义参考。"""

    code = "internal_error"
    http_status = 500

    def __init__(self, message: str = "", *, details: dict | None = None):
        super().__init__(message or self.__class__.__doc__ or self.code)
        self.message = message or self.__class__.__doc__ or self.code
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"error": self.code, "message": self.message, "details": self.details}


class AccountNotFound(ServiceError):
    """账号不存在。"""

    code = "account_not_found"
    http_status = 404


class AccountAlreadyExists(ServiceError):
    """账号 ID 已存在。"""

    code = "account_already_exists"
    http_status = 409


class UnknownIssuerError(ServiceError):
    """身份源 issuer 未在密钥库登记。"""

    code = "unknown_issuer"
    http_status = 400


class InjectedCrash(Exception):
    """测试注入的软崩溃。

    刻意 *不* 继承 ServiceError：它必须穿透幂等包装的 ServiceError 捕获，
    保证事务整体回滚且不写入任何幂等/审计记录，由调用方（测试）单独识别。
    """

    code = "injected_crash"
    http_status = 500

    def __init__(self, message: str = "injected crash"):
        super().__init__(message)
        self.message = message
        self.details: dict = {}


class AccountDisabled(ServiceError):
    """账号已禁用，新操作一律拒绝。"""

    code = "account_disabled"
    http_status = 403


class PasswordMismatch(ServiceError):
    """密码校验失败。"""

    code = "password_mismatch"
    http_status = 401


class SessionNotFound(ServiceError):
    """浏览器会话不存在或已被撤销。"""

    code = "session_not_found"
    http_status = 401


class SessionExpired(ServiceError):
    """浏览器会话已过期。"""

    code = "session_expired"
    http_status = 401


class LoginNotRecent(ServiceError):
    """会话存在，但近期登录证据已超过新鲜窗口。"""

    code = "login_not_recent"
    http_status = 401


class ChallengeNotFound(ServiceError):
    """挑战不存在。"""

    code = "challenge_not_found"
    http_status = 404


class ChallengeConsumed(ServiceError):
    """挑战已被一次性消费，不能重复使用。"""

    code = "challenge_consumed"
    http_status = 409


class ChallengeExpired(ServiceError):
    """挑战已超过到期时间。"""

    code = "challenge_expired"
    http_status = 410


class ChallengeRevoked(ServiceError):
    """挑战已被撤销（账号禁用会撤销全部待处理挑战）。"""

    code = "challenge_revoked"
    http_status = 410


class ChallengeSessionMismatch(ServiceError):
    """挑战绑定的浏览器会话与当前会话不同，禁止跨会话完成。"""

    code = "challenge_session_mismatch"
    http_status = 403


class ChallengeIssuerMismatch(ServiceError):
    """断言签发方与挑战绑定的目标 issuer 不同。"""

    code = "challenge_issuer_mismatch"
    http_status = 403


class AssertionBadSignature(ServiceError):
    """断言签名无效或格式损坏。"""

    code = "assertion_bad_signature"
    http_status = 401


class AssertionExpired(ServiceError):
    """断言已超过 exp。"""

    code = "assertion_expired"
    http_status = 401


class AssertionNotYetValid(ServiceError):
    """断言尚未到 nbf。"""

    code = "assertion_not_yet_valid"
    http_status = 401


class AssertionAudienceMismatch(ServiceError):
    """断言受众 aud 与本服务不匹配。"""

    code = "assertion_audience_mismatch"
    http_status = 403


class AssertionNonceMismatch(ServiceError):
    """断言 nonce 与挑战 nonce 不一致，属重放或张冠李戴。"""

    code = "assertion_nonce_mismatch"
    http_status = 403


class IdentityAlreadyBound(ServiceError):
    """该外部身份 (issuer, subject) 已绑定到某个内部账号，唯一键冲突。"""

    code = "identity_already_bound"
    http_status = 409


class IdentityNotLinked(ServiceError):
    """指定绑定不存在或已解除。"""

    code = "identity_not_linked"
    http_status = 404


class LastLoginMethod(ServiceError):
    """解绑后将不存在任何可用登录方式，拒绝解绑。"""

    code = "last_login_method"
    http_status = 409


class IdempotencyConflict(ServiceError):
    """request_id 已被使用，但请求参数与首次不同。"""

    code = "idempotency_conflict"
    http_status = 409


# 错误码 -> 异常类，供 runner / 反序列化使用
ERROR_BY_CODE: dict[str, type[ServiceError]] = {
    cls.code: cls
    for cls in list(globals().values())
    if isinstance(cls, type) and issubclass(cls, ServiceError) and cls is not ServiceError
}
