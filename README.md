# DSH-Encrypt（包名 `dsh-encrypt`）

DeepSeek Harness 的 **WebUI 管理密码的凭证加密插件**。一个文件，两种形态：

```
没有密码时（默认）:
  $DSH_HOME/.credentials.yaml          明文 YAML，与 dsh-credentials-local 完全一致

在 WebUI 设置 → 加密安全 中设置密码后:
  $DSH_HOME/.credentials.yaml          同一文件的内容被替换为加密文档：
  { format: dsh-encrypt-credentials,   AES-256-GCM 密文 + 双层 SHA3-256 指纹
    kdf: scrypt, salt, verifier,       （文档级 + 条目级）+ GCM 认证标签
    entries: { REF: { data, sha3 } } }

模型调用时:
  resolve(ref) → 校验 SHA3-256 → GCM 临时解密 → 交给请求，用后即弃；
  插件在两次操作之间从不缓存明文。
```

**不再需要在终端输口令**：密码的创建、解锁、修改、移除全部在浏览器设置页完成；dsh 重启后凭证库进入锁定状态，在设置页输入密码即解锁。忘记密码时，文件无法解密，只能清除文件重新配置凭证（诚实的设计：没有后门）。

## 状态机

```
            set-password                    (dsh 重启)            unlock
 明文 ──────────────────► 加密+已解锁 ───────────────► 加密+锁定 ────► 已解锁
   ▲                           │  ▲                                   │
   └────── clear-password ─────┘  └────────── change-password ────────┘
```

- 锁定状态下 dsh 照常启动（Web 服务不受影响），模型调用报 `VAULT_LOCKED`，设置页提供解锁入口；
- `$DSH_CREDENTIAL_PASSWORD` 环境变量可在启动时自动解锁（自动化部署用；提供的密码错误则启动失败）。

## 安装

```powershell
# 1. 把本包装进 profile 的依赖（本地开发用 junction，或 dsh plugin add <tgz>）
New-Item -ItemType Junction `
  -Path "$env:USERPROFILE\.dsh\profiles\node_modules\dsh-encrypt" `
  -Target "D:\Developments\DSH\DSH-Encrypt"

# 2. 编辑 $DSH_HOME/profiles/web/cordis.patch.yml：
#    - id: credentials          → disabled: true
#    - insert 两行:  dsh-encrypt（宿主 provider）、dsh-encrypt/web（浏览器密码路由）

# 3. 重启 dsh web，打开 设置 → 加密安全
```

安装后若尚未设置密码，行为与官方 `dsh-credentials-local` 完全相同（明文 `.credentials.yaml`）；在设置页设置密码即原地加密。此前由旧版插件生成的 `.credentials.vault.json` / `.credential-master.key` 不再被引用，可自行删除。

## 安全模型

| 威胁 | 防御 |
| --- | --- |
| 磁盘/备份泄露（设密后） | AES-256-GCM（ref 名绑定为 AAD，防条目互换） |
| 密文损坏 / 截断 / 换条目 | 条目级 `sha3(data)` + 文档级 `sha3(头部+entries)`，启动与热加载全量校验，损坏 fail-loud 或保留最后好快照 |
| 篡改密文并重算哈希 | GCM 认证标签（AEAD）→ `VAULT_KEY_MISMATCH` |
| 篡改 salt / scrypt 参数 | 文档级 SHA3-256 覆盖头部字段 → `VAULT_CORRUPTED` |
| 口令泄露 | scrypt（N=131072, r=8, p=1）+ 随机 salt；口令不落盘，只有 AEAD verifier |
| 内存驻留明文 | 明文仅在单次 `resolve()` 内存在，用后即弃；派生密钥在锁定/退出时清零 |

**诚实的边界**：JavaScript 字符串不可变，解密明文无法物理擦除——保证是"不持久化、不缓存、不入日志、引用及时消亡"。明文形态下 `.credentials.yaml` 与官方行为一致（0600，POSIX 强制校验）。

## 错误码

`VAULT_LOCKED` / `PASSWORD_WRONG` / `VAULT_CORRUPTED` / `VAULT_INVALID` / `VAULT_KEY_MISMATCH` / `VAULT_NOT_ENCRYPTED` / `VAULT_ALREADY_ENCRYPTED` / `PASSWORD_INVALID` / `MASTER_KEY_INVALID` / `MASTER_KEY_MISSING`。所有消息均不含口令、明文或密钥材料。

## 测试

```powershell
npm test                              # 42 项单元/集成测试
node test/client-smoke.mjs            # 浏览器 bundle 冒烟（ModuleLoader + SSR 渲染）
# 两阶段端到端（需 dsh web 实例）: E2E_BASE/E2E_HOME/E2E_PHASE=1|2
node test/e2e-webui.mjs
```

`lib/vault.js` 为纯密码学核心（零依赖，仅 `node:crypto`），可独立审计。
