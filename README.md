# dsh-encrypt

> **DSH 凭证加密插件**（bundle 形态）：一个文件（`$DSH_HOME/.credentials.yaml`）双形态存储——未设密码时是与官方 `dsh-credentials-local` 完全一致的明文 YAML；在「设置 → 加密安全」设置密码后，同一文件原地替换为 AES-256-GCM 密文文档（scrypt 派生密钥 + SHA3-256 完整性指纹）。浏览器只提交密码的 SHA3-256 摘要（前后端分离校验），模型请求按需临时解密，明文从不缓存；另提供「N 天免密登录」滑块（仅 localhost 生效）。

| 项目 | 值 |
| :-- | :-- |
| 形态 | **bundle**（`dsh.bundle.patch` → `cordis.patch.yml`，随 profile 启动，`dsh plugin add` 原生安装） |
| 版本 | `0.1.0-rc.7` |
| 依赖线 | npm rc.1（`@deepseek-ai/cordis@^4.0.1` 等 scoped 包） |
| 环境 | Node.js ≥ 18（官方教程建议 22+）；DSH `@deepseek-ai/dsh@0.0.1-rc.1`+ |
| License | [MIT](./LICENSE) |

## 解决的问题

DSH 默认的凭证存储把密钥以**明文 YAML** 写在 `$DSH_HOME/.credentials.yaml`。dsh-encrypt 用**同一个文件**提供可选的加密形态：设置密码前零改动、完全兼容；设置密码后文件内容被替换为密文文档，凭证只在模型调用发生时临时解密。

## 特性

- **单文件双形态**：明文 YAML ↔ `dsh-encrypt-credentials` 密文 JSON 原地互转，不产生第二个文件、不迁移路径
- **WebUI 全生命周期**：设置密码 / 解锁 / 修改密码 / 移除密码，全部在「设置 → 加密安全」完成
- **AES-256-GCM**：每条凭证独立随机 nonce，凭证引用名绑定为 GCM AAD（换位即认证失败）
- **SHA3-256 双重完整性**：条目级指纹 + 覆盖文档头部的文档级指纹，损坏文件在启动时即被拒绝（绝不当作“空库”）
- **scrypt 密码派生**（N=131072, r=8, p=1，约 128 MiB）：密码不落盘，仅存盐与 AEAD 验证器
- **摘要校验（前后端分离）**：WebUI 用纯 JS Keccak-f[1600] 计算密码的 SHA3-256，只 POST `{ digest }` 到后端；后端用 scrypt 拉伸摘要并与 AEAD 验证器匹配，原始密码不离开浏览器
- **免密登录滑块**：设置「多少天免密」（0 = 每次都输密码 / 1–30 天 / 永远），解锁成功后签发 256 位票据（HttpOnly Cookie），磁盘只存被 AEAD 包裹的密钥副本；到期或票据不匹配即失效
- **仅 localhost 免密与改密**：非本机访问强制每次都输密码，且不能设置/修改/移除密码（后端强制，返回 `LOCAL_ONLY`）
- **按请求解密**：明文只存活于单次操作，不缓存、不进日志；密钥在锁定/卸载时清零
- **热重载**：外部编辑明文即时生效；外部加密即时转锁定；损坏的中间状态保留最后一个好快照
- **原子写 + 文件锁**：写入经 `dsh-atomic-write`，POSIX 上强制 `0600` 权限（启动即校验）
- **自动化解锁**：`DSH_CREDENTIAL_PASSWORD` 环境变量在启动时解锁（适合 headless）

## 形态与架构

本插件是 **bundle** 形态（`package.json` + `dsh.bundle.patch` → `cordis.patch.yml`），由三个组合行构成：

| 组合行 | 入口 | 注入 | 职责 |
| :-- | :-- | :-- | :-- |
| `dsh-encrypt` | `dsh-encrypt`（`lib/index.js`） | —（`CredentialProvider` 服务） | `EncryptedCredentialProvider`：替换被禁用的基础 `credentials` 行，在同一 `ctx.credentials` 接缝上提供双形态存储 |
| `dsh-encrypt-web` | `dsh-encrypt/web`（`lib/web.js`） | `webServer`、`credentials` | 浏览器密码路由（5 条 `/api/credentials.*`），headless 组合不需要 |
| `dsh-encrypt/client` | `package.json` 的 `dsh.client` 声明 | `slots` | 「设置 → 加密安全」面板（web 组合自动挂载） |

替换方式遵循 bundle 生态边界：**不修改任何核心 row**（`tools`/`session`/`llm`/`web`/`permission` 均不动）。bundle patch 只做两件事——禁用基础 bundle 插入的明文 `credentials` 行，插入 `dsh-encrypt` 行。它提供同一个 `ctx.credentials` 接缝，因此 LLM 适配器、Models 页、web-search 等所有既有消费者**无需任何改动**。

## 安装

### 1. Profile Bundle（推荐）

先打包，再装进 profile（`dsh plugin add` 会把声明了 `dsh.bundle.patch` 的依赖自动 reconcile 进 bundles 列表）：

```sh
# 打包（files 字段仅含 lib 与 cordis.patch.yml，test/ 不入包）
npm pack
# → dsh-encrypt-0.1.0-rc.6.tgz

# web profile（设置页「加密安全」）
dsh plugin --profile web add ./dsh-encrypt-0.1.0-rc.6.tgz

# headless profile（一次性任务 / 自动化解锁；web 与 headless 是不同 profile，需分别安装）
dsh plugin --profile headless add ./dsh-encrypt-0.1.0-rc.6.tgz
```

本地源码目录同样可以直接安装（路径用 Windows 正斜杠形式）：

```sh
dsh plugin --profile web add "D:/path/to/DSH-Encrypt"
```

### 2. 挂载 Web 密码路由（设置面板需要，仅 web profile）

bundle patch 只插入 provider 行；浏览器密码路由是独立组合行，需在 profile 用户层挂载。编辑 `$DSH_HOME/profiles/web/cordis.patch.yml`，追加：

```yaml
- insert:
    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
```

### 3. 验证安装

```sh
dsh --profile web --dump-config | grep dsh-encrypt
# 期望：出现 dsh-encrypt 与 dsh-encrypt-web 两个行，且基础 credentials 行被禁用
```

### 4. 运行验证

```sh
# web：启动后打开「设置 → 加密安全」，应能看到加密面板
dsh web
```

```sh
# headless：环境变量自动解锁后，任何任务都应正常启动、凭证解析无 VAULT_LOCKED
DSH_CREDENTIAL_PASSWORD='<密码>' dsh run "运行一次最小任务验证凭证可用"
```

仓库另附两阶段真实重启 e2e（见[开发与测试](#开发与测试)），覆盖 明文→设密→损坏/恢复→重启锁定→解锁→改密→移除密码 全生命周期。

### 5. 手动安装与旧版本兼容（仅调试场景）

手动 patch 只作为旧快照兼容或调试方案，不是默认安装流程。完整手动层：

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
- id: credentials
  disabled: true

- insert:
    - id: dsh-encrypt
      name: 'dsh-encrypt'
      config:
        allowEnvFallback: true

    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
```

## 使用

全部操作在「设置 → 加密安全」完成（面板 id `encryption`）：

| 操作 | 前置状态 | 效果 |
| :-- | :-- | :-- |
| 设置加密密码（输入两次，至少 8 个字符） | 明文 | 同一文件原地替换为密文文档，进程保持解锁 |
| 解锁 | 加密+锁定（重启后） | 校验密码摘要并派生密钥，立即恢复模型调用 |
| 修改密码 | 加密+解锁 | 全部条目在新密钥下重加密 |
| 移除密码 | 加密+解锁 | 解密全部条目，文件恢复为明文 YAML |
| 免密登录时长（滑块） | 任意 | 0 = 每次都输密码；1–30 = N 天内免密；31 = 永远免密（均仅本机） |

滑块即改即存（松开即提交到 `/api/credentials.config`，只接受 localhost）。解锁成功后按当前滑块时长签发免密票据；改动滑块会作废旧票据，若当前已解锁则立即按新时长重新签发。免密期间重开页面自动解锁；到期后回到密码解锁。**非 localhost 访问始终需要输入密码，且不显示改密/移除密码入口**（后端同样强制）。

状态机：

```text
             set-password                    (restart)            unlock
  plain ──────────────────► encrypted+unlocked ──────► encrypted+locked ──► unlocked
    ▲                            │  ▲                                        │
    └────── clear-password ──────┘  └──────────── change-password ───────────┘
```

- **锁定期间**：web 服务照常运行；继承环境中的凭证仍可解析，文件内凭证解析抛 `VAULT_LOCKED`，`describe` 报告 `source: "locked"`——设置页即是解锁入口
- **免密窗口**：票据在签发时写入 `issuedAt` 与 `days`；`days: -1` 永不失效。滑块改动会立即作废旧票据
- **忘记密码**：设计上不可恢复（密码不落盘）；恢复手段 = 删除 `.credentials.yaml` 重新配置

## 凭证解析顺序

| 优先级 | 来源 | 说明 |
| :-- | :-- | :-- |
| 1 | 继承环境（launching environment） | 只读、高于受管文件；对被其遮蔽的引用写入会被拒绝 |
| 2 | 受管文件 `.credentials.yaml` | 明文或密文形态，可写 |
| 3 | `.env` 回退（project-env / user-env） | 低于受管文件，仅在文件无此引用时兜底 |

`allowEnvFallback: false` 可关闭第 1、3 层（严格仅文件策略）。

## 磁盘格式

**明文形态**（未设密码，与 `dsh-credentials-local` 完全一致）：

```yaml
OPENCODE_GO_API_KEY: sk-…
```

**密文形态**（设密码后，同一文件的内容被替换）：

```json
{
  "format": "dsh-encrypt-credentials",
  "version": 2,
  "algorithm": "aes-256-gcm+sha3-256",
  "kdf": "scrypt",
  "kdfInput": "sha3-256-password",
  "n": 131072, "r": 8, "p": 1,
  "salt": "<base64url>",
  "verifier": { "data": "<base64url>", "sha3": "<hex>" },
  "remember": {
    "salt": "<base64url>", "issuedAt": 1755000000000, "days": 7,
    "cipher": { "data": "<base64url>", "sha3": "<hex>" }
  },
  "entries": {
    "OPENCODE_GO_API_KEY": { "data": "<base64url>", "sha3": "<hex>" }
  },
  "sha3": "<document fingerprint>"
}
```

- `kdfInput: "sha3-256-password"`：scrypt 的输入是密码的 SHA3-256 摘要（浏览器计算），原始密码不进后端
- `verifier` 是固定明文的 AEAD 密文，用于在不接触任何真实凭证的前提下校验摘要
- `remember` 仅在签发过免密票据时存在：`cipher` 是在票据密钥（SHA3-256(域名‖salt‖票据)）下 AEAD 包裹的主密钥；票据本身只存在于浏览器 HttpOnly Cookie，永不落盘；`days: -1` 表示永远
- 文档级指纹覆盖 `sha3` 以外的全部字段（含 salt、成本参数与 remember 块）；条目级指纹覆盖各自的密文 blob
- 密码与票据从不落盘

## HTTP 路由（web 行）

仅 `POST application/json`（与官方 /api 相同的跨站写护栏）；响应 `{ ok: true, value }` 或 `{ ok: false, code, message }`，错误消息不含密码或任何密钥材料：

| 路径 | 请求体 | 作用 |
| :-- | :-- | :-- |
| `/api/credentials.status` | `{}` | 返回 `{ format, unlocked, local, remember: { days, active, issuedAt, expiresAt } }`；localhost 且携带免密 Cookie 时先尝试票据解锁 |
| `/api/credentials.unlock` | `{ digest }` | 密码摘要解锁（64 位小写 hex SHA3-256）；localhost 成功后再按滑块签发免密 Cookie |
| `/api/credentials.set-password` | `{ digest }` | 明文 → 密文（**仅 localhost**） |
| `/api/credentials.change-password` | `{ digest }` | 重加密（需已解锁，**仅 localhost**，作废旧票据） |
| `/api/credentials.clear-password` | `{}` | 密文 → 明文（需已解锁，**仅 localhost**，作废旧票据） |
| `/api/credentials.config` | `{ action: "get" }` / `{ action: "set", rememberDays }` | 读取状态或设置免密天数（-1 = 永远，0 = 每次，1–30；**set 仅 localhost**） |

所有路由只接受 `POST application/json`。密码本身永不出现在任何请求体里——浏览器只提交 `digest`（可用 `node -p "require('crypto').createHash('sha3-256').update('密码').digest('hex')"` 计算）。

headless 组合不挂载 web 行，因此没有 HTTP 面。

## 配置项

```yaml
config:
  path: ''            # 凭证文件绝对路径；未设置时取 $DSH_HOME/.credentials.yaml
  dshHome: ''         # Harness home（通常由运行时注入，无需手动设置）
  allowEnvFallback: true          # 允许继承环境与 .env 回退层
  passwordEnv: DSH_CREDENTIAL_PASSWORD  # 启动自动解锁的环境变量名
  watch: true         # 监听文件变化热重载
  debounceMs: 100     # 热重载防抖（毫秒）
```

| 字段 | 类型 | 默认值 | 说明 |
| :-- | :-- | :-- | :-- |
| `path` | string | `$DSH_HOME/.credentials.yaml` | 凭证文件绝对路径（运行时注入 `dshHome` 计算默认值） |
| `dshHome` | string | 运行时注入 | Harness home |
| `allowEnvFallback` | boolean | `true` | 是否启用继承环境与 `.env` 回退层 |
| `passwordEnv` | string | `DSH_CREDENTIAL_PASSWORD` | 启动自动解锁密码的环境变量名 |
| `watch` | boolean | `true` | 是否监听文件热重载 |
| `debounceMs` | number | `100` | 热重载防抖毫秒数（≥ 0） |
| `rememberDays` | number | `0` | 免密登录天数：`0` = 每次都输密码，`1..30` 天，`-1` = 永远（补丁配置的初始值；滑块运行时值写入 `$DSH_HOME/.dsh-encrypt.json` 并优先生效） |

## 安全模型

**保证**：

- 静态存储只含密文；内存快照在密文形态下只保存密文记录
- 每条目随机 12 字节 nonce；引用名作为 GCM AAD，记录换位会认证失败
- 双层 SHA3-256 指纹 + GCM 认证标签：篡改且重算指纹的攻击仍会以 `VAULT_KEY_MISMATCH` 失败（与错误主密钥不可区分——这是 AEAD 的诚实答案）
- 密码经 scrypt（N=131072, r=8, p=1）派生，只存盐与 AEAD 验证器
- POSIX 上凭证文件必须是 owner-only（`0600`），否则启动直接拒绝（`chmod 600` 修复）；Windows 无 mode 可查，保护由创建 API 与 OS ACL 表达
- 密钥（KEK）在锁定/卸载时清零（`zeroizeBuffer`）

**诚实边界**：

- JavaScript 字符串不可变：解密出的明文无法在内存中清零。给出的保证是**不持久化、不缓存、不进日志**，以及操作结束即丢弃引用
- 解锁期间主密钥必须驻留内存（否则无法解密任何条目），请以操作系统账户与 `0600` 文件保护
- 忘记密码无法找回（设计如此）；唯一恢复手段是清除凭证文件后重新配置

## 错误码

`VaultError` 携带稳定的机器可读 `code`，消息永不含明文/密文/密钥材料：

| code | 含义 |
| :-- | :-- |
| `PASSWORD_WRONG` | 摘要与验证器不匹配（错误密码在触碰任何条目之前即被拒绝） |
| `PASSWORD_INVALID` | 摘要不是 64 位小写 hex 的 SHA3-256 |
| `LOCAL_ONLY` | 该操作（改密/移除密码/免密设置）仅允许 localhost |
| `REMEMBER_EXPIRED` | 免密票据已超过其窗口，需重新输入密码 |
| `REMEMBER_INVALID` | 免密票据与本凭证库不匹配（或库中无票据） |
| `VAULT_LOCKED` | 凭证库已锁定；在「设置 → 加密安全」解锁（或导出 `DSH_CREDENTIAL_PASSWORD`） |
| `VAULT_NOT_ENCRYPTED` | 尚未设置密码，无锁可解/无密可改/可除 |
| `VAULT_ALREADY_ENCRYPTED` | 已设密码；修改密码请用 `change-password` |
| `VAULT_CORRUPTED` | SHA3-256 完整性校验失败，错误中指名出问题的引用 |
| `VAULT_INVALID` | 文档结构非法（版本、算法、字段形状） |
| `VAULT_KEY_MISMATCH` | GCM 认证失败：主密钥不匹配，或密文被替换 |
| `PASSWORD_INVALID` / `MASTER_KEY_INVALID` | 参数或密钥材料非法 |

## 兼容性与升级

- **v0.1.0-rc.6 → rc.7（本次更新）**：文档版本升级为 v2（KDF 输入从密码改为密码的 SHA3-256 摘要）。v1 密文文档无法被 rc.7 读取——升级前请先在旧版「移除密码」恢复明文，或删除 `.credentials.yaml` 重新配置；明文形态不受影响
- 与官方 `credentials` 接缝 **drop-in**：LLM 适配器、Models 页、web-search 等消费者零改动
- 官方凭证 RPC（如 `credentials.set`）在两种形态下照常工作；锁定状态下写入会以 `VAULT_LOCKED` 拒绝
- 明文形态文件可被 `dsh-credentials-local` 直接读取——移除本插件前先「移除密码」即可无缝回退
- 对外导出：`dsh-encrypt`（provider）、`dsh-encrypt/vault`（零依赖密码学核心）、`dsh-encrypt/web`（路由）、`dsh-encrypt/client`（浏览器包）

## 卸载与回滚

1. **先移除密码**：设置页「移除密码」把文件恢复为明文（否则基础 `credentials` 行无法理解密文文档）
2. 移除 web 行：删除 `$DSH_HOME/profiles/web/cordis.patch.yml` 中的 `dsh-encrypt-web` insert
3. 移除 bundle：

```sh
dsh plugin --profile web remove dsh-encrypt
dsh plugin --profile headless remove dsh-encrypt
```

基础 `credentials` 行随 bundle 移除自动恢复启用，明文文件继续可用。

## 开发与测试

```sh
npm install        # devDependencies 自包含（scoped rc.1 依赖线）
npm test           # node --test：42 个单元测试（vault 30 + provider 12）
```

额外验证脚本：

```sh
node test/client-smoke.mjs     # 浏览器包 ModuleLoader/SSR 冒烟
# 两阶段真实重启 e2e（目标实例与 home 均显式传入，不硬编码回环地址）：
node test/e2e-webui.mjs --base http://localhost:3199 --home <dsh-home> --phase 1
node test/e2e-webui.mjs --base http://localhost:3199 --home <dsh-home> --phase 2
```

测试套件仅本地回归用，不随 npm 包分发（`files` 仅含 `lib` 与 `cordis.patch.yml`）。

## 许可证

[MIT](./LICENSE) · © 2026 Yauntyours
