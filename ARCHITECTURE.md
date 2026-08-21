# dsh-encrypt 架构

本分支以 upstream/master 的分层 TypeScript/toolchain 为安全基础，再增加一个 Stent sidecar 组合层。包根入口是 `src/fabric-entry.ts`：它**不替换**官方 credentials provider，只创建 sidecar controller 并注册 Stent seams。`src/index.ts` 保留 upstream provider-compatible 入口和核心实现，便于复用、测试以及后续迁移；发布包根 `.` 指向 `lib/fabric-entry.js`。

## 运行时所有权

| 组件                                                     | 所有权           | 责任                                                                        |
| :------------------------------------------------------- | :--------------- | :-------------------------------------------------------------------------- |
| `@deepseek-ai/dsh-credentials-local` / `credentials` row | 官方 provider    | provider 生命周期、环境层、官方 `.credentials.yaml` 读取和原生 watcher      |
| `dsh-encrypt-fabric`                                     | 本插件 Stent row | controller 生命周期、sidecar 文件、加密状态、Stent patch registration       |
| `@deepseek-ai/dsh-host-webserver`                        | host             | HTTP route table、upgrade table 和实际监听；本插件只通过 Stent 包装注册参数 |
| `lib/integrity.js` + manifest                            | 构建产物         | 启动时检查已发布文件和 `cordis.patch.yml` 是否完整一致                      |

`cordis.patch.yml` 中 Stent row 默认 `disabled: true`，由 `stent-dsh` profile 开启。官方 `credentials` row 不得被禁用；`scripts/check-patch-drift.mjs` 会在构建后验证这一点。

## 模块边界

| 层              | 目录/入口                                                            | 职责                                                                          | 允许依赖                          |
| :-------------- | :------------------------------------------------------------------- | :---------------------------------------------------------------------------- | :-------------------------------- |
| 领域            | `src/domain`                                                         | vault/provider model、稳定错误码、Valibot schemas                             | `src/shared`、Valibot             |
| 应用            | `src/application`                                                    | upstream 密码操作、remember、队列和 provider policy                           | 领域层、基础设施端口              |
| 基础设施        | `src/infrastructure`                                                 | Argon2id/AES-GCM、vault 文档、状态文件、权限和运行时配置                      | 领域层、共享校验                  |
| 传输            | `src/transport`                                                      | HTTP 结构、请求 schema、限量读取和边界错误                                    | 领域层、Valibot                   |
| 安全            | `src/security`、`src/leak-guard.ts`                                  | literal leak matching、HTTP/WS redaction 和 socket fence                      | 窄安全接口                        |
| 客户端          | `src/client`、`src/client.ts`                                        | 浏览器 SHA3、API、remember storage 和设置页状态                               | 浏览器标准 API                    |
| Stent 组合      | `src/fabric-entry.ts`、`src/fabric-handlers.ts`                      | Cordis config、controller 创建、6 个 patch descriptor/handler、WebServer 注入 | Stent API、官方 credentials seams |
| Sidecar runtime | `src/fabric-controller-runtime.js`、`src/plain.ts`、`src/migrate.ts` | marker/sidecar 生命周期、兼容的 invoke hooks、旧格式迁移                      | vault、lockout、home/atomic-write |
| 兼容入口        | `src/index.ts`、`src/vault.ts`、`src/web.ts`、`src/client.ts`        | 稳定导出和组合，不承载新的底层协议                                            | 上述分层模块                      |

Stent controller 的实现被有意隔离成一个只负责运行时迁移的兼容模块；`src/fabric-controller.ts` 提供 typed constructor/path facade，避免 legacy lifecycle 方法污染 upstream 的 isolated declaration 生成。它没有独立的 provider service，也不会绕过官方 credentials row。

## Vault 与 sidecar 组合

`src/vault.ts` 维持公共加密导出；实现由以下模块组合：

1. `domain/vault/model.ts` 定义文档常量、类型和 `VaultError`。
2. `domain/vault/schemas.ts` 校验 JSON/YAML credential document。
3. `infrastructure/crypto/vault-crypto.ts` 处理 Argon2id、旧 scrypt、AES-GCM、SHA3 和 key zeroization。
4. `infrastructure/persistence/vault-document.ts` 处理序列化、结构校验和文档 fingerprint。
5. `application/password-service.ts` / `remember-service.ts` 处理密码、ticket 和恢复。
6. `fabric-controller-runtime.js` 将相同 vault primitive 映射到 sidecar 文件和官方 provider hooks。

sidecar 状态转换：

```text
.credentials.yaml (官方 plaintext)
        │ set-password: encrypt, write sidecar first
        ▼
.credentials.yaml (comment-only marker)
.credentials.encrypt.yaml (ciphertext)
        │ restart / lock / unlock
        └── controller resolves encrypted entries and writes only sidecar
```

两个文件格式故意不互相兼容。启动时看到 legacy single-file encrypted document 会抛 `VAULT_MIGRATION_REQUIRED`，看到 sidecar 与 marker 不一致会抛 `VAULT_INVALID`；不会把异常内容当作空凭证库继续运行。

## Stent patch 契约

`src/fabric-handlers.ts` 是唯一的 executable descriptor source；YAML 只携带 bundle metadata。当前稳定 ID/操作如下：

- `credentials-resolve` / `credentials-describe`: official `resolve`/`describe` 的 `after`；
- `credentials-set` / `credentials-unset`: official `set`/`unset` 的 `around`；
- `webserver-http-register` / `webserver-upgrade-register`: host route registration 的 `before`，可选目标。

所有 credentials target 都绑定 `@deepseek-ai/dsh-credentials-local` 的 `src/index.ts` / `lib/index.js`，版本范围 `<0.2.0`。修改 handler 时必须同时运行：

```sh
pnpm build
node scripts/check-patch-drift.mjs
```

drift check 会比较 `id`、`required`、`target`、`operation`，并拒绝任何禁用官方 `credentials` row 的 patch。

## Web 与安全边界

Stent entry 等待 `webServer` 或 `httpServer` 注入，然后以 `{ credentials: controller, ...webContext }` 调用 `src/web.ts`。这样 upstream Web transport 不需要知道 Stent，仍可复用：

- Valibot 请求结构与 body size/timeout fence；
- Host authority + loopback socket 双重判定；
- cookie 默认的 remember ticket，显式 `header` 通道兼容特殊 WebView；
- 已有 route table 和未来注册 route 的 HTTP/WS literal redaction。

核心业务不把 HTTP handler 直接放进 controller；handlers 只负责 Stent call arguments/return values，web 层负责请求解析、错误映射和 response header。

## 完整性、并发与校验

- `tsdown.config.ts` 与 client config 使用 `writeBundle` 在所有输出写入后生成 `lib/integrity-manifest.json`；manifest 覆盖所有 `lib/**` 产物和 `cordis.patch.yml`。
- `@deepseek-ai/schemastery` 只用于 Cordis 静态 `Config` 边界；upstream application/transport/persistence 对不可信结构使用 Valibot 或显式 fail-closed 检查。
- upstream `OperationQueue` 提供失败隔离的串行修改；sidecar controller 另有自己的 queue，保证 watcher、set/unset、密码修改按顺序写入。
- leak detection 使用不可变 literal matcher，不把凭证内容拼入动态 regex；marker basename 检查属于纯格式识别，不承担秘密匹配。
- Node/build 入口保留 `assertRuntimeCompat()` 和 `loadAndVerifyIntegrity()`，完整性清单用于发现安装损坏，不是目录写权限攻击下的签名信任根。

## 变更规则

- 新磁盘字段先加入领域类型/schema，再加入 fingerprint 的规范化字段顺序；sidecar 字段还要覆盖 legacy/marker 迁移路径。
- 新 HTTP 操作先定义精确 request schema，禁止用字符串强制转换接受错误类型。
- 新密码学能力留在 `infrastructure/crypto`，Stent controller 只组合 primitive，不复制 AEAD/KDF 实现。
- 新 Stent seam 必须同时更新 `PATCH_IDS`、`PATCH_OPERATIONS`、`patchStubs()`、`cordis.patch.yml` 和 drift/integration tests。
- 新输出通道复用 security redaction；必须明确记录无法扫描的二进制边界。
- `lib/`、`.map`、`.d.ts` 和 integrity manifest 只由 `pnpm build` 生成；发布前运行 `pnpm pack --dry-run`。本地完成后按类别提交，未得到明确要求不得 push。
