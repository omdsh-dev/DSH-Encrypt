# dsh-encrypt

> **DSH 凭证加密 Stent sidecar**：不替换官方 `dsh-credentials-local` provider，而是在 Stent profile 中挂载一个加密控制器，拦截凭证 provider 的 `resolve` / `describe` / `set` / `unset` 接缝，并通过 host WebServer 接缝安装密码路由和输出脱敏。设密后，官方 `.credentials.yaml` 保留为 comment-only marker，密文存放在旁车 `.credentials.encrypt.yaml`。

| 项目       | 值                                                          |
| :--------- | :---------------------------------------------------------- |
| 形态       | bundle（`dsh.bundle.patch` → `cordis.patch.yml`）           |
| 版本       | `0.1.0-rc.12`                                               |
| 兼容运行时 | dsh `0.1.x`（加载时校验，跨线抛 `UNSUPPORTED_DSH`）         |
| 依赖线     | Cordis / DSH seam 包精确钉版；Stent 使用 `@oh-my-dsh/stent` |
| 环境       | Node.js ≥ 24；DSH `0.1.x`                                   |
| License    | [MIT](./LICENSE)                                            |

## 设计目标

- **官方 provider 仍是 owner**：保留 `credentials` row，不禁用它；官方 provider 继续负责环境层、YAML marker 读取、生命周期和兼容行为。
- **Stent 只改接缝**：`dsh-encrypt-fabric` row 默认 `disabled: true`，仅由 `stent-dsh` profile 启用；patch descriptor 与运行时 `patchStubs()` 自动做 drift check。
- **旁车存储**：明文迁移为 `.credentials.yaml` marker + `.credentials.encrypt.yaml` 密文文件，避免让官方 parser 看到密文；旧版单文件密文通过迁移 CLI 显式转换。
- **安全默认值**：Argon2id + AES-256-GCM、SHA3-256 指纹、0600 原子写、文件锁、锁定退避、remember ticket 和 HTTP/WebSocket Leak Guard。
- **跟随 upstream/master 安全层**：领域模型、Valibot 输入校验、不可变 literal matcher、操作队列、完整性 manifest、runtime compatibility fence 和 TypeScript build toolchain 均来自上游重构；Stent adapter 作为独立组合层接入。

## 安装与构建

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm build
pnpm pack

dsh plugin --profile stent-dsh add ./dsh-encrypt-0.1.0-rc.12.tgz
```

`@node-rs/argon2` 使用预编译 native binary；平台缺失时可执行 `pnpm rebuild @node-rs/argon2`。发布前 `prepack` 会重新生成 `lib/integrity-manifest.json` 并检查 patch drift。

源码目录也可以直接作为 profile plugin 安装；修改后重新启动对应 dsh profile 即可加载新的 bundle。不要直接手工改写 `lib/`，它是 `pnpm build` 的产物。

## Bundle 行与职责

`cordis.patch.yml` 只插入以下 Stent row，并**不会**禁用官方 `credentials` row：

```yaml
- insert:
    - id: dsh-encrypt-fabric
      name: 'dsh-encrypt'
      disabled: true
      config:
        allowEnvFallback: true
        trustedHosts: []
        stent:
          patches: # 6 个与 src/fabric-handlers.ts 同步的 descriptor
```

`stent-dsh` profile 启用这个 disabled row；普通 `dsh` profile 会跳过它，因此不会意外改变官方 provider。启用后：

| 层            | 入口                                         | 职责                                                          |
| :------------ | :------------------------------------------- | :------------------------------------------------------------ |
| 官方 provider | `@deepseek-ai/dsh-credentials-local`         | 继续拥有 provider 生命周期、环境解析和 marker 文件            |
| Stent adapter | `lib/fabric-entry.js`                        | 创建 sidecar controller、注册 6 个 Stent patch、挂载 Web 行为 |
| Web 安全层    | `lib/web.js` + host `webServer`/`httpServer` | 密码操作、remember ticket、Host fence、HTTP/WS 输出脱敏       |
| 浏览器 client | `lib/client.js`                              | SHA3-256 摘要、设置页和 cookie/header remember 流程           |

Stent adapter 通过 `ctx.inject(['webServer'], ...)` 和 `ctx.inject(['httpServer'], ...)` 适配不同 host；若没有 WebServer 服务，只挂载凭证 hooks，不会创建第二个 HTTP server。

## 使用与状态机

所有密码操作可由设置页完成，也可以调用本插件的 `/api/credentials.*` 路由：

```text
plain official file
       │ set-password
       ▼
encrypted sidecar + marker, unlocked
       │ restart / lock
       ▼
encrypted sidecar + marker, locked ── unlock / remember ──► unlocked
       │
       └──────────── change-password ────────────────┘
```

| 操作          | 前置状态             | 效果                                                             |
| :------------ | :------------------- | :--------------------------------------------------------------- |
| 设置密码      | plain                | 读取官方 YAML，写入 sidecar 密文，再原子写 marker；进程保持解锁  |
| 解锁          | encrypted + locked   | 校验 SHA3 摘要并派生密钥，恢复 sidecar 凭证解析                  |
| 修改密码      | encrypted + unlocked | 验证旧摘要，全部条目重新加密，旧 remember ticket 失效            |
| remember 天数 | 任意                 | `0` 每次输入；`1–30` 天；`-1` 永久；密码和 ticket 操作仅允许本机 |

加密状态下，Stent `resolve` / `describe` 在官方 provider 未返回文件值时从 sidecar 提供值；`set` / `unset` 由 sidecar 接管。官方 provider 返回了未加密文件值时会 fail closed，而不是静默合并两套存储。继承环境层可按 `allowEnvFallback` 保留；环境值不会被 sidecar 覆盖写入。

## 磁盘格式

### 明文状态

设密前，官方 provider 正常拥有 `$DSH_HOME/.credentials.yaml`：

```yaml
OPENAI_API_KEY: sk-...
```

### 加密状态

设置密码后，官方文件只保留 marker：

```yaml
# dsh-encrypt: encrypted sidecar
# Credential values are stored in .credentials.encrypt.yaml.
```

`.credentials.encrypt.yaml` 是经过 schema 校验的 JSON/YAML 文档，包含 Argon2id 参数、salt、AEAD verifier、remember block、条目级 ciphertext/fingerprint 和文档级 SHA3-256。每个条目的引用名绑定为 AES-GCM AAD；文件损坏、格式混用、权限过宽或符号链接都会 fail closed。

自定义路径时，`encryptedPath` 指向 sidecar，`statePath` 指向锁定/remember 状态文件；默认分别为 `.credentials.encrypt.yaml` 和 `$DSH_HOME/.dsh-encrypt.json`。不要把 sidecar 当作官方 provider 的 plaintext 文件，也不要把密文直接放回 `.credentials.yaml`。

## 旧版单文件迁移

`origin/master` 的单文件密文格式与 Stent sidecar 格式有意不兼容。升级前先停止 dsh，再运行：

```sh
pnpm build
pnpm exec dsh-encrypt-migrate \
  --path "$DSH_HOME/.credentials.yaml"
```

CLI 只验证旧密文结构、写入新的 `.credentials.encrypt.yaml`，最后把官方文件替换为 marker；它不会解锁或打印凭证。也可以作为库调用 `migrateLegacySidecar({ path, encryptedPath })`。已有 sidecar、权限过宽或非旧版密文都会拒绝覆盖。

## Web API 与脱敏

Stent Web 行会注册以下 exact routes（均要求 `POST application/json`，请求体上限和超时由 upstream transport 校验）：

| 路径                               | 请求                       | 作用                                                 |
| :--------------------------------- | :------------------------- | :--------------------------------------------------- |
| `/api/credentials.status`          | `{}`                       | 状态、锁定和 remember 快照；本机 ticket 会先尝试解锁 |
| `/api/credentials.unlock`          | `{ digest }`               | 本机解锁；成功后按 remember 策略签发 ticket          |
| `/api/credentials.set-password`    | `{ digest }`               | plain → sidecar encrypted；仅本机                    |
| `/api/credentials.change-password` | `{ oldDigest, digest }`    | 验证旧摘要并重加密；仅本机                           |
| `/api/credentials.config`          | `{ action, rememberDays }` | 读取或修改 remember 天数；修改仅本机                 |

默认 remember ticket 使用 HttpOnly、SameSite=Strict cookie；`rememberChannel: 'header'` 才会兼容 localStorage/header 通道并在响应中返回 ticket。非回环访问不能执行密码操作；`trustedHosts` 只扩展状态/配置读取的 Host authority，不扩大密码操作的 socket+Host 本机判定。

解锁期间解析过的凭证值进入 Leak Guard。Stent 对 host WebServer 的现有 route table 和后续注册进行包装，HTTP 文本响应及 WebSocket 文本帧离开进程前都会做 earliest/longest literal redaction；二进制帧和工具主动外传不在该保证范围内。

## 配置项

`dsh-encrypt-fabric` row 的主要配置：

| 字段                                                   | 默认值                             | 说明                                     |
| :----------------------------------------------------- | :--------------------------------- | :--------------------------------------- |
| `path`                                                 | `$DSH_HOME/.credentials.yaml`      | 官方文件路径；默认跟随 official provider |
| `dshHome`                                              | runtime home                       | 状态文件和默认路径的 home                |
| `encryptedPath`                                        | 同目录 `.credentials.encrypt.yaml` | sidecar 密文路径                         |
| `statePath`                                            | `$DSH_HOME/.dsh-encrypt.json`      | lockout/remember 状态                    |
| `allowEnvFallback`                                     | `true`                             | 是否保留继承环境和 `.env` 回退           |
| `passwordEnv`                                          | `DSH_CREDENTIAL_PASSWORD`          | 启动时自动解锁的环境变量                 |
| `watch` / `debounceMs`                                 | `true` / `100`                     | sidecar/marker 热重载                    |
| `rememberDays`                                         | `0`                                | `-1` 永久，`0` 每次，`1–30` 天           |
| `rememberChannel`                                      | `cookie`                           | `cookie`（默认）或 `header`              |
| `leakGuard`                                            | `true`                             | 输出脱敏总开关                           |
| `leakMinMaskLength` / `leakMaxMaskLength`              | `8` / `256`                        | literal mask 长度窗口                    |
| `maxUnlockAttempts` / `lockoutBaseMs` / `lockoutMaxMs` | `5` / `30000` / `900000`           | 失败次数和指数退避                       |
| `trustedHosts`                                         | `[]`                               | 非回环状态读取允许的 Host authority      |

`stent.patches` 是 bundle 元数据，不要手工复制到其他入口；修改 handler 后请运行 `pnpm check:patch`，它会比较 YAML descriptor 与 `patchStubs()` 并确认官方 `credentials` row 未被禁用。

## 安全边界

保证包括：

- sidecar 和 state 文件在 POSIX 上要求 owner-only 权限；原子写、目录权限和文件锁防止半写入与并发覆盖；
- Argon2id 派生、AES-256-GCM authenticated encryption、条目和文档 SHA3-256 fingerprint；
- 设密后 plaintext marker 与 ciphertext sidecar 分离，格式混用、旧单文件格式和损坏文档拒绝启动；
- lockout 计数持久化、指数退避、pending unlock admission cap 和 `Retry-After`；
- Host fence + loopback socket fence、请求 Valibot 校验、完整性 manifest 和 runtime compatibility guard；
- 密钥在锁定/卸载时清零，解密 Buffer 在操作结束时清零；plaintext 字符串因 JavaScript 不可变而只能保证不持久化、不缓存、不进日志；
- 完整性 manifest 是安装损坏检测，不是能抵抗目录写权限攻击的签名信任根。

忘记密码不可恢复；同一 OS 用户可以删除或编辑自己的状态文件，因此 lockout 只防在线猜测，不是账户隔离。摘要本身等价于口令，`header` remember channel 对页面脚本可读，默认 cookie 通道更安全。

## 开发检查

```sh
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm check:patch
pnpm pack --dry-run
```

构建产物在 `lib/`，来源在 `src/`；不要手工提交不匹配的 manifest。改动完成后只创建本地分类 commit，除非明确要求，否则不 push。
