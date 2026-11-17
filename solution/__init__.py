"""本地账号关联服务（本地 HMAC 断言模拟联合身份源）。

模块划分：
- errors:  统一错误码与异常层次
- clock:   可注入时钟（系统时钟 / 固定可调的假时钟）
- crypto:  base64url、HMAC-SHA256 签名与恒时校验、规范哈希
- idp:     模拟身份提供方（IdP）与密钥库
- db:      SQLite 连接、WAL 配置与建表脚本
- service: 关联服务核心（挑战、绑定、解绑、禁用、幂等、审计、崩溃点）
- runner:  cases.json 用例执行引擎（含真实多进程与屏障）
"""

__version__ = "1.0.0"

# 本服务的逻辑受众标识；断言 aud 必须与之相等
DEFAULT_AUDIENCE = "local-linking-service"
