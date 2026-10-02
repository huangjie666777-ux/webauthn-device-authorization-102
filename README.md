# WebAuthn Level 2 登录后端（FastAPI）+ OAuth 2.0 设备授权

不使用任何成品 WebAuthn 服务端库，仅依赖 `cryptography`、`cbor2`、FastAPI 与
标准库实现 WebAuthn Level 2 注册 / 登录，并按 **RFC 8628** 提供 OAuth 2.0
设备授权 grant（Device Authorization Grant），供无浏览器设备经用户同意访问
账号（无前端）。

## 支持范围（刻意收窄）

- 算法：仅 **ES256**（ECDSA over P-256 / SHA-256）。
- 证明：仅 **`none` attestation**（`attStmt` 必须为空 map）。
- 标志：强制 `UP=1`、`UV=1`；注册强制 `AT=1`；禁止扩展（`ED=1` 拒绝）。
- 禁止跨源：`clientDataJSON.crossOrigin` 为真即拒绝；不接受 `topLevelOrigin` 的跨源场景。
- 每个用户名只允许一个凭据；已有账号再次注册返回 `409`，不会覆盖。
- 登录 `allowCredentials` 只返回该用户名下登记的凭据；finish 时服务端再次核对凭据归属，不接受属于其他用户的凭据。

## 服务端信任边界

- RP ID、RP Name、Origin、数据库路径全部来自**服务端配置**（环境变量），请求中自报的 origin / rpId 一律不采信。
- 校验内容：`clientDataJSON.type`（`webauthn.create` / `webauthn.get`）、`challenge`、`origin`、`crossOrigin`；认证器数据的 `rpIdHash = SHA-256(rpId)`、`UP`、`UV`、（注册时）`AT`、AAGUID/凭据 ID/COSE 公钥。
- COSE 公钥必须是 `kty=2 (EC2)`、`alg=-7 (ES256)`、`crv=1 (P-256)`，`x`/`y` 各 32 字节，转换为 DER 后存储并验签。
- 登录签名覆盖 `authenticatorData || SHA-256(clientDataJSON原始字节)`，服务端用收到的原始字节拼接验签，**绝不重新序列化 JSON**。

## 挑战、计数与会话

- 挑战为 32 字节 `secrets` 随机数，绑定用户名、操作类型（register/login）及用户 handle；TTL **5 分钟**。
- 消费通过单条原子 `UPDATE ... WHERE consumed=0 AND expires_at>now RETURNING` 完成，运行在 `BEGIN IMMEDIATE` 事务中；并发重放最多成功一次。
- 仅在全部校验通过、凭据写入 / 计数更新 / 会话写入的同一事务中提交；失败整体回滚，不残留半注册用户、不消费挑战。
- 签名计数：注册时保存认证器上报的**真实初始 `sign_count`**（不再固定存 0）；服务端与认证器计数**都为 0 时允许**（无计数器设备）；否则新计数必须**严格增大**，回退 / 停滞即拒绝。计数更新与挑战消费原子提交。
- 登录成功签发 `secrets.token_urlsafe(32)` 随机不透明令牌，有效期 **30 分钟**。数据库仅存 `SHA-256(token)`；退出删除摘要；重启后未过期会话继续有效。

## 数据存储

SQLite（WAL，`foreign_keys=ON`，`busy_timeout=30s`），表：

- `users(id, username)`、`credentials(credential_id, public_key DER, sign_count)`
- `challenges(..., challenge, expires_at, consumed, user_handle)`
- `sessions(token_hash, user_rowid, expires_at)`
- `device_authorizations(device_code_hash, user_code, client_id, scope, status, user_rowid, expires_at, interval_seconds, last_poll_at)`
- `device_grants(user_rowid, client_id, scope, token_hash, expires_at, revoked, device_code_hash)`
- `user_code_attempts(user_code, attempted_at)`（用户码猜测限流）

新表均以 `CREATE TABLE IF NOT EXISTS` 增量创建，兼容已有数据库文件与原有接口。

## HTTP 接口

所有二进制字段使用 base64url（无填充）。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/register/options` | `{username}` → PublicKeyCredentialCreationOptions |
| POST | `/register/finish` | 注册响应：`clientDataJSON`、`attestationObject`、`userHandle` |
| POST | `/login/options` | `{username}` → 含该用户 `allowCredentials` 的请求参数 |
| POST | `/login/finish` | 断言：`credentialId`、`clientDataJSON`、`authenticatorData`、`signature`、`userHandle` |
| GET | `/me` | `Authorization: Bearer <token>` 查询身份 |
| POST | `/logout` | 销毁当前令牌 |
| GET | `/healthz` | 健康检查 |

错误统一返回 `{"error": "..."}`，状态码 `400/401/403/404/409`。

## OAuth 2.0 设备授权（RFC 8628）

供无浏览器设备（公共客户端）在用户同意后访问账号。仅配置一个公共客户端
（默认 `client_id=device-public`），注册 scope 只有 `profile`：未知客户端返回
`invalid_client`，申请或兑换时携带 `profile` 以外的 scope 返回 `invalid_scope`。

### 设备侧接口（表单 `application/x-www-form-urlencoded`）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/oauth/device_authorization` | 入参 `client_id`、可选 `scope`；返回 `device_code`、易输入的 `user_code`（`XXXX-XXXX`）、`verification_uri`、`expires_in=600`、`interval=5` |
| POST | `/oauth/token` | `grant_type=urn:ietf:params:oauth:grant-type:device_code` + `device_code` + `client_id`，按协议返回令牌或错误 |
| GET | `/oauth/profile` | 用设备令牌（Bearer）读取授权用户本人资料；仅含 `username`/`userId`/`client_id`/`scope` |

`device_code` 为 128 位以上随机值，数据库只存 `SHA-256` 摘要；与一个不含
易混字符的随机 `user_code` 绑定，申请 **10 分钟** 过期。轮询错误严格区分：

- `authorization_pending`：用户尚未批准；
- `slow_down`：轮询早于要求间隔，每次该错误后间隔**累计增加 5 秒**；
- `access_denied`：用户拒绝；
- `expired_token`：设备码已过期；
- `invalid_client`/`invalid_grant`：客户端未知 / 设备码未知或已消费。

轮询时间与间隔持久化到 SQLite，重启后未过期流程继续有效。错误客户端的请求
在读取申请前即被拒绝，不能改变申请状态。

### 用户同意接口（必须携带原 WebAuthn 登录令牌）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/device/consent?user_code=XXXX-XXXX` | 查询该用户码对应的客户端名称、scope 与当前状态；**查询本身不批准** |
| POST | `/device/decision` | JSON `{user_code, approve}`；身份取自登录会话，批准或拒绝 |
| GET | `/oauth/grants` | 列出本人的设备授权 |
| DELETE | `/oauth/grants/{id}` | 撤销本人的某次设备授权 |

- 终态（已批准 / 已拒绝 / 已消费）**不能被覆盖**；设备**不能**用 `user_code` 兑换。
- 用户码查询有防猜测限制：同一用户码 10 分钟内失败超过 5 次返回 `429`（尝试记录持久化）。
- 批准后设备码消费（`approved → consumed`）与设备令牌写入在**同一个
  `BEGIN IMMEDIATE` 事务**内完成，并发兑换最多一次成功；被拒绝或过期后不可能发出令牌。

### 设备令牌的权限边界

- 设备令牌 30 分钟有效，仅存 `SHA-256` 摘要，绑定用户、客户端、scope 与对应设备码。
- 设备令牌**只能**访问 `GET /oauth/profile`（本人资料）；不能调用
  `/device/consent`、`/device/decision`、`/oauth/grants` 等审批 / 管理接口，也不能当登录令牌用。
- 用户撤销授权后，对应设备令牌**立即失效**（`/oauth/profile` 返回 401），原登录会话不受影响。

### curl 示例

```bash
# 设备申请
curl -X POST http://localhost:8000/oauth/device_authorization \
  -d 'client_id=device-public' -d 'scope=profile'

# 用户在已登录的浏览器/终端上查看并批准（LOGIN_TOKEN 为 /login/finish 所得）
curl 'http://localhost:8000/device/consent?user_code=SNHL-KTKT' \
  -H "Authorization: Bearer $LOGIN_TOKEN"
curl -X POST http://localhost:8000/device/decision \
  -H "Authorization: Bearer $LOGIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"user_code":"SNHL-KTKT","approve":true}'

# 设备每 5 秒轮询兑换
curl -X POST http://localhost:8000/oauth/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'device_code=...' -d 'client_id=device-public'

# 读取资料 / 列出授权 / 撤销
curl http://localhost:8000/oauth/profile -H "Authorization: Bearer $DEVICE_TOKEN"
curl http://localhost:8000/oauth/grants   -H "Authorization: Bearer $LOGIN_TOKEN"
curl -X DELETE http://localhost:8000/oauth/grants/1 -H "Authorization: Bearer $LOGIN_TOKEN"
```

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | `localhost` | Relying Party ID（验 rpIdHash） |
| `WEBAUTHN_RP_NAME` | `WebAuthn Demo` | RP 展示名 |
| `WEBAUTHN_ORIGIN` | `http://localhost:8000` | 唯一信任的浏览器 origin |
| `WEBAUTHN_DB` | `./webauthn.sqlite` | SQLite 文件（重启保留凭据与会话） |
| `OAUTH_DEVICE_CLIENT_ID` | `device-public` | 唯一允许的公共客户端 ID |
| `OAUTH_DEVICE_CLIENT_NAME` | `Device Client (Public)` | 同意页展示名 |
| `OAUTH_DEVICE_CLIENT_SCOPES` | `profile` | 该客户端注册的 scope（空格分隔） |
| `OAUTH_DEVICE_CODE_TTL` | `600` | 设备码 / 用户码有效期（秒） |
| `OAUTH_DEVICE_INTERVAL` | `5` | 初始轮询间隔（秒），`slow_down` 每次 +5 |
| `OAUTH_DEVICE_TOKEN_TTL` | `1800` | 设备令牌有效期（秒） |
| `OAUTH_USER_CODE_MAX_ATTEMPTS` | `5` | 用户码查询窗口内最大尝试次数 |
| `OAUTH_USER_CODE_WINDOW` | `600` | 用户码尝试计数窗口（秒） |

> 生产环境 RP ID 应为注册域的可注册后缀，origin 必须与浏览器实际地址完全一致。

## 运行

```bash
# 1) 启动服务（使用 .venv/bin/python）
./run_server.sh

# 2) 另开终端，跑真实签名的 curl 全流程演示
./demo/run_demo.sh alice http://localhost:8000

# 3) OAuth 2.0 设备授权全流程（申请 -> 用户查看/批准 -> 轮询兑换 -> 资料 -> 撤销）
./demo/run_device_demo.sh alice http://localhost:8000
```

`demo/soft_authenticator.py` 是一个纯演示用软件认证器：生成并持久化真实
P-256 私钥，按规范构造 `clientDataJSON`、认证器数据、`none` 证明对象，
并用私钥对断言做真实 ES256 签名。状态保存在
`demo/authenticator_state.json`（私钥文件，勿用于真实身份）。

`demo/run_demo.sh` 完整演示：options → 软件认证器生成凭据 → finish →
登录 options → 真实签名断言 → `/me` → `/logout` → 退出后 401。

`demo/run_device_demo.sh` 完整演示 RFC 8628 流程：软件认证器注册 / 登录拿到
用户同意令牌 → 设备表单申请 → 用户 `/device/consent` 查询、`/device/decision`
批准 → 设备轮询（先 `authorization_pending`）→ 兑换设备令牌 →
`/oauth/profile` → `/oauth/grants` 列出 → 撤销后设备令牌立即 401，原会话仍可用。

## 测试

```bash
.venv/bin/python -m pytest -q
```

覆盖：完整注册/登录/查询/退出、重复注册 409、未知用户 404、错误 origin、
`crossOrigin`、错误 rpIdHash、篡改签名、重新序列化 clientDataJSON 后验签
失败、签名计数 0/0 与严格递增、挑战 5 分钟过期、跨用户凭据拒绝，以及
8 线程并发重放同一登录断言仅有一次成功。设备授权测试覆盖：申请/批准/兑换/
读取资料/撤销完整流程、未知客户端与越权 scope、`slow_down` 间隔累计 +5、
拒绝/过期、错误客户端与伪造设备码、终态不可覆盖、用户码猜测限流（429）、
8 线程并发兑换仅一次成功、初始 `sign_count` 真实落库、申请状态重启后续用。

## 代码结构

```
app/config.py        # 服务端配置（不信任请求）
app/db.py            # SQLite 连接、schema、BEGIN IMMEDIATE 事务
app/repository.py    # 事务仓储：用户/凭据/挑战/会话
app/webauthn.py      # base64url、clientDataJSON/认证器数据/COSE/CBOR 解析与验签
app/service.py       # 注册、登录、计数、令牌编排
app/device_service.py # RFC 8628 设备申请/同意/轮询兑换/授权管理编排
app/http_api.py      # FastAPI 路由（WebAuthn + OAuth 设备授权）
tests/               # pytest 与测试用软件认证器
demo/                # 软件认证器 CLI 与 curl 演示脚本
```
