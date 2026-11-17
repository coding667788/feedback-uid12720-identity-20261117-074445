# 本地账号关联服务（联合身份双向证明与竞态一致性）

把两个身份源（IdP）的**外部身份**绑定到同一**内部账号**的本地服务。身份源用
本地 HMAC 签名断言模拟，协议由本项目自定义，不连接任何真实账号、不使用 Docker、
不依赖第三方库（除标准库外无其他依赖；Python 3.12 / Windows / 仅 CPU）。

---

## 1. 它解决什么问题

核心约束（对应题目要求）：

1. **外部身份唯一键 = `(issuer, subject)`**。邮箱 `email` 仅作展示字段，
   数据库对 email 不建任何唯一约束，**绝不据此自动合并账号**。
2. 发起关联必须**同时**证明两件事：
   - 当前内部账号的**近期登录状态**（有效的浏览器会话 + 登录新鲜窗口）；
   - 待绑定外部身份的**所有权**（IdP 用共享密钥对含一次性 nonce 的断言签名）。
   挑战（challenge）同时绑定 *内部账号 + 目标 issuer + 浏览器会话 + nonce +
   到期时间*，完成后一次性消费。
3. 两个独立进程可能把**同一外部身份同时绑定到不同内部账号**。数据库保证只有
   一个胜者：关联写入、挑战消费、幂等记录、审计事件在**同一个 SQLite 事务**里
   提交；`(issuer, subject)` 上的部分唯一索引是跨进程一致性的最终防线。
4. 原请求丢响应后，可凭相同 `request_id` 查到既有结果；**换参数复用同一
   `request_id` 必须拒绝**（`idempotency_conflict`）。
5. 解绑必须保留至少一种可用登录方式；关联、解绑、禁用按数据库提交顺序线性化。
   账号禁用提交后启动的新操作一律失败；旧挑战在重新启用后**不会自动复活**。
6. 提供**可注入时钟**（`FakeClock`）与**崩溃点**（提交前/提交后退出、软崩溃）。

---

## 2. 目录结构

```
.
├── solution/                 # 交付的可运行包
│   ├── __init__.py
│   ├── __main__.py           # CLI: python -m solution --input ... --output ...
│   ├── errors.py             # 稳定错误码 + 异常层次
│   ├── clock.py              # SystemClock / 可注入 FakeClock
│   ├── crypto.py             # base64url、HMAC-SHA256、恒时比较、PBKDF2
│   ├── idp.py                # 模拟 IdP + issuer 密钥库
│   ├── db.py                 # SQLite WAL、显式 BEGIN IMMEDIATE、schema
│   ├── service.py            # 关联服务核心（事务/幂等/挑战/崩溃点）
│   ├── runner.py             # cases.json 声明式执行引擎 + 多进程编排
│   └── worker.py             # spawn 子进程入口（模块级函数）
├── tests/                    # unittest 自动化测试（真实多进程）
│   ├── _helpers.py
│   ├── test_crypto_idp.py
│   ├── test_service_logic.py
│   ├── test_concurrency.py   # 真实 spawn 双进程 + Barrier/Event
│   ├── test_crash_recovery.py# 真实 os._exit 崩溃 + 重启重试
│   ├── test_end_to_end.py    # 驱动整个 cases.json
│   └── test_cli.py           # 子进程方式验证 CLI 契约
├── samples/
│   └── issuer_keys.json      # 两个模拟 IdP 的固定 HMAC 密钥（可重放）
├── cases.json                # 13 个声明式验收用例
└── README.md
```

运行产物（`*.db`、`.runtime-tmp/`、`__pycache__`）均已在 `.gitignore` 忽略。

---

## 3. 快速开始

```bash
# 入口一：跑声明式用例，退出码 0=全通过，1=有断言失败，2=输入/参数错误
python -m solution --input cases.json --output result.json

# 入口二：跑全部自动化测试（含真实双进程竞态与崩溃重启）
python -m unittest discover -s tests -v
```

整套 `cases.json` 在本机约 15 秒内跑完；`unittest` 全套（57 个测试）约 2–3 分钟，
其中多进程用例每个都要 spawn 独立 Python 进程。

---

## 4. 身份断言协议（本题自定义）

断言是一个紧凑令牌，结构类似 JWT 但只用标准库实现：

```
base64url(canonical(header)) . base64url(canonical(payload)) . base64url(HMAC-SHA256)
```

- `header = {"alg": "HS256", "typ": "local-assertion"}`
- 规范 JSON：键排序、无空白、UTF-8（`canonical_bytes`），保证签名字节确定。
- `payload` 字段：

| 字段 | 含义 |
|---|---|
| `iss` | 身份源标识，必须等于挑战绑定的目标 issuer |
| `sub` | 该身份源内的外部主体；与 `iss` 组成外部身份唯一键 |
| `email` | **仅展示**，不参与任何身份判定或合并 |
| `aud` | 受众，必须等于 `local-linking-service` |
| `nonce` | 挑战随机数，必须与挑战 nonce 完全一致（防重放/张冠李戴） |
| `iat` / `nbf` / `exp` | 签发/生效/过期时间（Unix 秒），用注入时钟判定 |
| `jti` | 断言唯一 id，审计追踪 |

验证方（service）只信任 `samples/issuer_keys.json` 里登记过的 issuer，用对应
共享密钥**独立验签**，签名比较走 `hmac.compare_digest`（恒时）。验签后再依次
校验 `iss / aud / nbf / exp / nonce`。

> 注意：`aud` 被调包但仍用正确密钥签名时，签名是有效的，拒绝发生在受众检查，
> 错误码为 `assertion_audience_mismatch`；而篡改签名字节或用错误密钥签名时
> 在验签层就失败，错误码为 `assertion_bad_signature`。

---

## 5. 关联流程（双向证明）

```
create_account ──> login(口令) ──> 浏览器会话(session_token, last_login_at)
                                        │
start_challenge(账号, 会话, issuer) ──> 校验: 账号启用 + 会话有效 + 登录新鲜
                                        └─> 生成 challenge{账号, issuer, 会话,
                                            nonce, expires_at=now+300s}
用户向 IdP 证明身份 ──> IdP 用 HMAC 签发含该 nonce 的断言
                                        │
complete_challenge(挑战, 会话, 断言) ──> 同一事务内:
        1. 挑战存在且 pending、未过期、未撤销
        2. 账号仍启用；会话有效、新鲜，且 == 挑战绑定的会话（换会话即拒）
        3. 断言验签 + iss/aud/nbf/exp/nonce 全部匹配
        4. (issuer, subject) 无活跃绑定（预检 + 唯一索引兜底）
        5. 写 external_identities、挑战置 consumed、写幂等记录、写审计
        6. COMMIT（崩溃点 before_commit / after_commit 可注入）
```

- **登录新鲜窗口**默认 300 秒：`now - last_login_at > 300` 则发起/完成挑战报
  `login_not_recent`，需重新登录。
- 浏览器会话默认 TTL 3600 秒，过期报 `session_expired`；被禁用或登出后置
  `revoked=1`，报 `session_not_found`。
- 挑战默认 TTL 300 秒，到期报 `challenge_expired`；成功消费后再用报
  `challenge_consumed`（一次性）。

---

## 6. 数据库与并发模型（为什么只有一个胜者）

SQLite 配置（`db.py`）：

- `journal_mode=WAL`：一个写事务与多个读事务并发；所有写事务在库级串行。
- 每个事务显式 `BEGIN IMMEDIATE`：进入事务即拿写锁，配合 `busy_timeout=10000`，
  第二个进程阻塞排队而不是立刻 `SQLITE_BUSY`。**写事务的提交顺序即线性化顺序**。
- 连接 `isolation_level=None`（autocommit），事务边界完全由代码显式控制，崩溃点
  语义不受驱动隐式 BEGIN 干扰。
- `synchronous=FULL`，提交即落盘。

关键约束：

```sql
CREATE UNIQUE INDEX ux_active_issuer_subject
    ON external_identities(issuer, subject) WHERE active = 1;
```

部分唯一索引只约束**活跃**绑定：解绑（`active=0`）后同一身份可重新绑定，但任意
时刻一个 `(issuer, subject)` 全局只能有一条活跃绑定。两个进程同时抢绑时，先
提交者成功，后提交者在该索引上撞 `IntegrityError`，被转成
`identity_already_bound` 并整体回滚——**不依赖任何进程内锁**。

每个写操作（关联/解绑/禁用/登录/建号）都把业务写、挑战状态、幂等记录、审计事件
放进**同一个事务**，因此它们要么全部可见、要么全部不可见。

---

## 7. 幂等语义

`idempotency_requests` 以 `request_id` 为主键，存首次请求的操作类型、参数规范
哈希（`canonical_hash`）与响应：

- 同 `request_id` + 同参数：返回首次存储的响应，附 `replayed=true`，**不再执行
  业务、不再写审计**。
- 同 `request_id` + 不同操作或不同参数：`idempotency_conflict`。
- 业务失败也占用 `request_id`（状态 `failed`）：同参重放得到同样失败，换参仍被
  拒绝。
- 两个进程用**完全相同**的 `request_id` 和参数并发时，主键约束保证只落一条记录，
  一个首次成功、另一个拿到重放结果（见 `ConcurrentIdempotencyTest`）。

---

## 8. 解绑与禁用规则

- 可用登录方式数 = 活跃外部绑定数 + 本地口令（`password_ref` 非空算 1）。
- 解绑前若方式数 ≤ 1，报 `last_login_method`，拒绝解绑。
- `remove_local_password` 是测试/管理动作，把账号转成纯联邦账号；若此时没有任何
  外部身份会拒绝（否则将失去全部登录方式）。
- `disable_account` 在一个事务内：账号置禁用、**撤销全部会话**、**撤销全部 pending
  挑战**、写审计。此后：
  - 任何新操作在账号启用检查处即报 `account_disabled`；
  - 旧挑战状态已是 `revoked`，`enable_account` 只恢复启用标志，**不复活会话也不
    复活挑战**，旧挑战永远报 `challenge_revoked`。

---

## 9. 崩溃注入与重启

崩溃点通过 `crash_plan={"<operation>.<point>": "<mode>"}` 注入：

| mode | 行为 | 退出码 |
|---|---|---|
| `exit_before_commit` | 事务 COMMIT 前 `os._exit`，模拟进程崩溃 | 86 |
| `exit_after_commit` | COMMIT 持久化后、响应返回前 `os._exit`，模拟响应丢失 | 87 |
| `raise_before_commit` | 抛 `InjectedCrash`（不继承 ServiceError），事务回滚、进程存活 | 0 |

- 提交前崩溃：数据库无绑定、无审计、无幂等记录、挑战仍 pending；重启后用同一
  `request_id` 重试**首次成功**。
- 提交后崩溃：绑定已落盘、挑战已 consumed；重启后同 `request_id` 重放返回既有
  结果，不产生第二条绑定或审计。

崩溃动作在独立 spawn 进程里执行，父进程随后新建 service 打开同一数据库文件来
模拟重启，全程不共享连接或锁。

---

## 10. 输入 / 输出 Schema

### 10.1 输入 `cases.json`

```jsonc
{
  "schema_version": 1,
  "seed": 20261117,                 // 固定随机种子，保证可重放
  "clock": {"type": "fake", "start": 1700000000},
  "audience": "local-linking-service",
  "login_freshness_seconds": 300,
  "session_ttl_seconds": 3600,
  "challenge_ttl_seconds": 300,
  "issuers": [                       // 可引用项目内密钥文件
    {"issuer": "https://idp-alpha.example/", "key_file": "samples/issuer_keys.json"}
  ],
  "cases": [
    {
      "id": "case01_...",
      "title": "...",
      "steps": [
        {"op": "create_account", "request_id": "r1", "account_id": "acct1",
         "password": "pw", "expect": {"status": "ok", "fields": {...}}},
        {"op": "parallel", "workers": [{"steps": [...]}, {"steps": [...]}],
         "expect": {"workers_ok": 2, "aggregate": [
            {"path": "count_where:outcome.status==ok", "op": "eq", "value": 1}]}},
        {"op": "crash_and_retry", "crash_point": "complete_challenge.before_commit",
         "crash_mode": "exit_before_commit", "crash_step": {...}, "retry_step": {...}}
      ]
    }
  ]
}
```

步骤 `op` 一览：`create_account` / `login` / `start_challenge` /
`mint_assertion` / `complete_challenge` / `unlink` / `disable_account` /
`enable_account` / `remove_local_password` / `advance_clock` / `get_account` /
`find_identity` / `list_identities` / `list_challenges` / `list_audit` /
`parallel` / `crash_and_retry`（另有仅测试编排用的 `_sync`）。

- 字符串里可用 `$var` 或 `${a.b}` 引用前序 `capture` 的变量。
- `expect.fields` 的字段路径相对步骤 outcome，支持 `data.x.y` 完整路径、简写
  `x.y`，以及列表下标 `data.challenges.0.status`。
- 谓词：`eq / ne / contains / not_contains / exists / size / ge / le / gt / lt /
  regex`。
- 并行聚合：`values:<path>` / `count:<path>` / `count_where:<path>==<value>`。

### 10.2 输出 `result.json`

```jsonc
{
  "schema_version": 1,
  "seed": 20261117,
  "summary": {"cases": 13, "cases_passed": 13, "cases_failed": 0,
              "checks_total": 199, "checks_failed": 0},
  "cases": [
    {
      "case_id": "...", "title": "...", "passed": true,
      "checks_total": 25, "checks_failed": 0, "case_error": null,
      "steps": [
        {"op": "...", "step_id": "s0",
         "outcome": {"status": "ok", "error": null, "data": {...}},
         "checks": [{"assertion": "status", "expected": "ok",
                     "actual": "ok", "passed": true}],
         "passed": true}
      ]
    }
  ]
}
```

业务失败的步骤 `outcome.status="error"` 且带稳定 `error` 错误码；并行步骤额外含
`workers`（每个真实进程的结果）与崩溃步骤的 `crash`（mode/point/exitcode）。

---

## 11. 错误码表

| code | 触发条件 |
|---|---|
| `account_not_found` / `account_already_exists` | 账号不存在 / ID 重复 |
| `account_disabled` | 账号已禁用，新操作被拒 |
| `password_mismatch` | 口令校验失败或账号无本地口令 |
| `session_not_found` / `session_expired` | 会话不存在/被撤销 / 已过期 |
| `login_not_recent` | 登录证据超过新鲜窗口 |
| `challenge_not_found` / `challenge_consumed` | 挑战不存在 / 已一次性消费 |
| `challenge_expired` / `challenge_revoked` | 挑战过期 / 随禁用被撤销 |
| `challenge_session_mismatch` | 换了浏览器会话完成挑战 |
| `challenge_issuer_mismatch` | 断言 issuer 与挑战目标不符 |
| `assertion_bad_signature` | 断言结构损坏或 HMAC 验签失败 |
| `assertion_audience_mismatch` | 签名有效但受众不匹配 |
| `assertion_expired` / `assertion_not_yet_valid` | 断言 exp/nbf 不满足 |
| `assertion_nonce_mismatch` | nonce 与挑战不一致（重放/调包） |
| `identity_already_bound` | `(issuer, subject)` 活跃绑定唯一冲突（抢绑败者） |
| `identity_not_linked` | 解绑目标不存在或已解绑 |
| `last_login_method` | 解绑会失去最后一种登录方式 |
| `idempotency_conflict` | request_id 复用但参数/操作不同 |
| `unknown_issuer` | issuer 未在密钥库登记 |
| `injected_crash` | 测试注入的软崩溃（事务已回滚） |

---

## 12. 验收场景 ↔ 用例 / 测试映射

| 题目要求场景 | cases.json | unittest |
|---|---|---|
| 同邮箱不同主体、不自动合并 | `case01` | `SameEmailDistinctSubjectTest` |
| 交换浏览器会话 | `case02` | `ChallengeSessionBindingTest` |
| 并发抢绑（真实两进程+屏障，唯一胜者） | `case03` | `ConcurrentRaceBindingTest`（含 5 轮重复） |
| 双重解绑最后两个入口 | `case04` + `case04b` | `ConcurrentDoubleUnlinkTest` / `UnlinkProtectionTest` |
| 提交前/后崩溃与重启重试 | `case07` / `case08` | `HardCrashBefore/AfterCommitTest` 等 |
| 禁用线性化、旧挑战不复活 | `case09` | `DisableLinearizationTest` / `DisableVersusLinkLinearizationTest` |
| 断言篡改攻击面 | `case10` | `AssertionValidationTest` |
| 登录新鲜度/挑战到期 | `case11` | `FreshnessAndExpiryTest` |
| 解绑后重绑、跨 issuer 并存 | `case12` | `UnlinkProtectionTest.test_rebind...` |
| 幂等重放与 request_id 冲突 | `case06` | `IdempotencyTest` / `ConcurrentIdempotencyTest` |

### 真实多进程是怎么复现的

- 所有并发/崩溃测试都用 `multiprocessing.get_context("spawn")` 启动**独立操作
  系统进程**，每个进程各自 `connect()` 自己的 SQLite 连接，绝不共享 Python 锁或
  连接对象；测试会断言两个子进程 PID 互不相同且不同于父进程。
- 抢绑/双解绑：`multiprocessing.Barrier(3)`（两子进程 + 父进程）对齐后同时放行，
  让两个进程在同一时刻进入写事务竞争，最终只由数据库唯一索引裁决胜者。
- 禁用 vs 关联的两种提交顺序：用跨进程 `Event` 门控（`_sync` 步骤）确定性地安排
  谁先拿锁提交，而不是靠 `sleep` 猜调度；父进程轮询数据库确认前一操作落库后再
  放行后一操作。
- 断言全部检查具体状态、错误码、行数、PID 与审计证据，没有"打印成功即通过"。

### 关于可重放

固定种子 + FakeClock 让三次运行的**判定结果（每个用例/断言的 passed、summary、
并发不变量）字节级稳定**。唯一会跨运行变化的是竞态里"哪个进程赢"（胜者账号 id、
由 PID 参与生成的主键），这是真实并发的本质；不变量（恰一个胜者、败者错误码、
终态唯一绑定）每次都成立。

---

## 13. 设计取舍与边界

- 只用标准库（`sqlite3 / hmac / hashlib / multiprocessing / json / base64 /
  random / time`），题目允许的 `cryptography` 实际未使用——HMAC-SHA256 与
  PBKDF2 标准库已足够。
- 所有操作局限在项目目录下的临时数据库与本机模拟组件，无网络、无外部服务。
- `random.Random(seed)` 仅用于生成不可预测但可重放的 nonce/id；涉及跨进程主键时
  再混合 PID 与实例计数器避免碰撞。生产环境应改用 `secrets`。
- 模拟 IdP 的"错误密钥签名"用一把确定性外来密钥，便于构造可复现的验签失败用例。
