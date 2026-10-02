# WebAuthn Level 2 登录后端（FastAPI）

不使用任何成品 WebAuthn 服务端库，仅依赖 `cryptography`、`cbor2`、FastAPI 与
标准库实现 WebAuthn Level 2 注册 / 登录（无前端）。

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
- 签名计数：服务端与认证器计数**都为 0 时允许**（无计数器设备）；否则新计数必须**严格增大**，回退 / 停滞即拒绝。计数更新与挑战消费原子提交。
- 登录成功签发 `secrets.token_urlsafe(32)` 随机不透明令牌，有效期 **30 分钟**。数据库仅存 `SHA-256(token)`；退出删除摘要；重启后未过期会话继续有效。

## 数据存储

SQLite（WAL，`foreign_keys=ON`，`busy_timeout=30s`），表：

- `users(id, username)`、`credentials(credential_id, public_key DER, sign_count)`
- `challenges(..., challenge, expires_at, consumed, user_handle)`
- `sessions(token_hash, user_rowid, expires_at)`

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

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WEBAUTHN_RP_ID` | `localhost` | Relying Party ID（验 rpIdHash） |
| `WEBAUTHN_RP_NAME` | `WebAuthn Demo` | RP 展示名 |
| `WEBAUTHN_ORIGIN` | `http://localhost:8000` | 唯一信任的浏览器 origin |
| `WEBAUTHN_DB` | `./webauthn.sqlite` | SQLite 文件（重启保留凭据与会话） |

> 生产环境 RP ID 应为注册域的可注册后缀，origin 必须与浏览器实际地址完全一致。

## 运行

```bash
# 1) 启动服务（使用 .venv/bin/python）
./run_server.sh

# 2) 另开终端，跑真实签名的 curl 全流程演示
./demo/run_demo.sh alice http://localhost:8000
```

`demo/soft_authenticator.py` 是一个纯演示用软件认证器：生成并持久化真实
P-256 私钥，按规范构造 `clientDataJSON`、认证器数据、`none` 证明对象，
并用私钥对断言做真实 ES256 签名。状态保存在
`demo/authenticator_state.json`（私钥文件，勿用于真实身份）。

`demo/run_demo.sh` 完整演示：options → 软件认证器生成凭据 → finish →
登录 options → 真实签名断言 → `/me` → `/logout` → 退出后 401。

## 测试

```bash
.venv/bin/python -m pytest -q
```

覆盖：完整注册/登录/查询/退出、重复注册 409、未知用户 404、错误 origin、
`crossOrigin`、错误 rpIdHash、篡改签名、重新序列化 clientDataJSON 后验签
失败、签名计数 0/0 与严格递增、挑战 5 分钟过期、跨用户凭据拒绝，以及
8 线程并发重放同一登录断言仅有一次成功。

## 代码结构

```
app/config.py        # 服务端配置（不信任请求）
app/db.py            # SQLite 连接、schema、BEGIN IMMEDIATE 事务
app/repository.py    # 事务仓储：用户/凭据/挑战/会话
app/webauthn.py      # base64url、clientDataJSON/认证器数据/COSE/CBOR 解析与验签
app/service.py       # 注册、登录、计数、令牌编排
app/http_api.py      # FastAPI 路由
tests/               # pytest 与测试用软件认证器
demo/                # 软件认证器 CLI 与 curl 演示脚本
```

