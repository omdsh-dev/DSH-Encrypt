# dsh-encrypt

> **DSH 凭证加密插件**(bundle 形态):一个文件(`$DSH_HOME/.credentials.yaml`)双形态存储——未设密码时是与官方 `dsh-credentials-local` 完全一致的明文 YAML;设置密码后,同一文件原地替换为 **AES-256-GCM 密文文档**(Argon2id 派生密钥 + SHA3-256 完整性指纹)。浏览器只提交密码的 SHA3-256 摘要(前后端分离),模型请求按需临时解密、明文从不缓存;内置**解锁爆破锁定、凭证泄露检测与输出脱敏、发行代码完整性自校验**,并与 dsh 运行时**三层解耦**(详见[部署架构](#部署架构dshenv-运行时与系统分离))。

| 项目       | 值                                                                                                          |
| :--------- | :---------------------------------------------------------------------------------------------------------- |
| 形态       | **bundle**(`dsh.bundle.patch` → `cordis.patch.yml`,随 profile 启动)                                         |
| 版本       | `0.1.0-rc.12`                                                                                               |
| 兼容运行时 | dsh `0.1.0-rc.7` 线(实测组合;跨线明确报 `UNSUPPORTED_DSH`)                                                  |
| 依赖线     | 接缝包精确钉版(cordis `4.0.1`、dsh-credentials 等 `0.1.0-rc.6`);独立包范围版(@node-rs/argon2/chokidar/yaml) |
| 环境       | Node.js ≥ 24;DSH `@deepseek-ai/dsh@0.0.1-rc.1+`                                                             |
| License    | [MIT](./LICENSE)                                                                                            |

## 特性

- **单文件双形态**:明文 YAML ↔ 密文 JSON 原地互转,不产生第二个文件、不迁移路径
- **AES-256-GCM**:每条凭证独立随机 nonce,引用名绑定为 GCM AAD(换位即认证失败)
- **SHA3-256 损坏检测**:条目级指纹 + 覆盖文档头部的文档级指纹,损坏文件启动即被拒绝(绝不当作“空库”);密文真实性由 AES-GCM 标签提供
- **Argon2id 密码派生**(m=64 MiB, t=3, p=1,OWASP 对齐):密码不落盘,仅存盐与 AEAD 验证器;旧版 scrypt(v2)密文仍可解锁并在解锁时自动升级
- **摘要校验(前后端分离)**:WebUI 用纯 JS Keccak-f[1600] 计算密码的 SHA3-256,只 POST `{ digest }` 到后端;原始密码不离开浏览器
- **解锁爆破锁定**:连续失败计数持久化(重启不清零),达阈值(默认 5 次)指数退避(30s 起、×2、上限 15min),HTTP 429 + `Retry-After`
- **凭证泄露检测与输出脱敏(Leak Guard)**:解析过的凭证值登记为掩码模式,WebUI 的 HTTP 响应体与 WebSocket 文本帧离开主机前替换为 `[REDACTED:dsh-encrypt]`(分块边界安全的流式脱敏;rc.12 起真正接线)
- **发行文件一致性自校验**:构建时生成 `lib/integrity-manifest.json`(`lib/` 全部构建文件与 `cordis.patch.yml` 的 SHA3-256),启动逐文件校验,并拒绝清单遗漏、越界文件名和内容不一致;该清单用于发现安装损坏,不作为防恶意改包的信任根
- **免密登录滑块**:0 = 每次输密码 / 1–30 天 / 永远;解锁成功后签发 256 位票据,**默认仅 HttpOnly Cookie**(响应体不回传);页面加载、**标签页重新可见/聚焦**时自动重试解锁,服务重启后切回页面即可
- **仅本机密码操作**:解锁、设密、改密和免密设置都要求 Host 回环 **且** socket 回环;带代理转发头的请求不会被当成本机请求
- **永远密文(ciphertext-only)**:设密后文件永不回退明文;外部明文替换在解锁态被立即重加密、锁定/启动态被拒绝(`plaintextForbidden`)
- **阅后即焚**:密文只在被使用的时刻解密,中间 Buffer 立即清零,密钥在锁定/卸载时清零
- **按请求解密**:明文只存活于单次操作,不缓存、不进日志
- **热重载** + **原子写 + 文件锁**(POSIX 强制 0600)+ **自动化解锁**(`DSH_CREDENTIAL_PASSWORD`)
- **运行时兼容护栏**:加载时探测运行中 dsh 版本,同 0.1.x 线不同 rc 打警告,跨线抛 `UNSUPPORTED_DSH`(fail-loud,替代静默失效)——这是与 dsh 解耦的最后一层保险

## 形态与架构

实现代码采用领域、应用、基础设施、传输、安全和客户端分层。`index.ts`、`vault.ts`、`web.ts`、`client.ts` 保留为兼容入口；磁盘结构与 HTTP 输入由 Valibot 校验，Cordis 静态配置继续使用宿主要求的 Schemastery。项目的字符语法和泄露匹配均使用显式解析，不使用正则表达式。完整边界与变更规则见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

bundle 形态由三个组合行构成:

| 组合行               | 入口                            | 注入                         | 职责                                                                             |
| :------------------- | :------------------------------ | :--------------------------- | :------------------------------------------------------------------------------- |
| `dsh-encrypt`        | `dsh-encrypt`(`lib/index.js`)   | —(`CredentialProvider` 服务) | 双形态存储:替换被禁用的基础 `credentials` 行,在同一 `ctx.credentials` 接缝上工作 |
| `dsh-encrypt-web`    | `dsh-encrypt/web`(`lib/web.js`) | `webServer`、`credentials`   | 浏览器密码路由(5 条 `/api/credentials.*`)+ 输出脱敏安装                          |
| `dsh-encrypt/client` | package.json 的 `dsh.client`    | `slots`                      | 「设置 → 加密安全」面板(web 组合自动挂载)                                        |

替换方式遵循 bundle 生态边界:不修改任何核心 row,只禁用基础 `credentials` 行并插入本插件行。LLM 适配器、Models 页、web-search 等既有消费者零改动(drop-in)。

## 安装

### 1. 打包并安装(bundle)

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm pack                      # prepack 自动重建 lib/integrity-manifest.json
dsh plugin --profile web add ./dsh-encrypt-0.1.0-rc.12.tgz
dsh plugin --profile headless add ./dsh-encrypt-0.1.0-rc.12.tgz   # 如需要 headless
```

`@node-rs/argon2` 为带预编译二进制的原生依赖,极少平台组合缺失时 `pnpm rebuild @node-rs/argon2` 即可。

**源码目录安装(本机当前方式)**:profile 的 `node_modules` 里建 junction 指向源码,源码改动即位于安装位置、重启生效,无需 `dsh plugin add`:

```sh
dsh plugin --profile web add "D:/Developments/DSH/DSH-Encrypt"
```

### 2. 挂载 Web 密码路由(仅 web profile)

bundle patch 只插入 provider 行;浏览器路由是独立组合行。在 `$DSH_HOME/profiles/web/cordis.patch.yml` 用户层追加:

```yaml
- insert:
    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
      config:
        trustedHosts: [] # LAN/隧道部署时才需要,见下
```

LAN 部署(如经 frp 隧道远程访问)需把放行的权威来源写进 `trustedHosts`(与官方 `connection` 行同源取值)。注意 `!!js` 表达式引用 `ctx.webRuntime` 时必须加**行级 `inject: [webRuntime]`**,否则加载器抛 `cannot get property "webRuntime" without inject`:

```yaml
- insert:
    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
      inject: [webRuntime]
      config:
        trustedHosts: !!js '[...ctx.webRuntime.trustedHosts, "app.internal.example"]'
```

### 3. 验证安装

```sh
dsh --profile web --dump-config | grep dsh-encrypt
# 期望:dsh-encrypt 与 dsh-encrypt-web 两个行在,基础 credentials 行被禁用
```

## 使用

全部操作在「设置 → 加密安全」完成(面板 id `encryption`):

| 操作                           | 前置状态          | 效果                                                     |
| :----------------------------- | :---------------- | :------------------------------------------------------- |
| 设置加密密码(两次,至少 8 字符) | 明文              | 同一文件原地替换为密文文档,进程保持解锁                  |
| 解锁                           | 加密+锁定(重启后) | 校验密码摘要并派生密钥,恢复模型调用                      |
| 修改密码                       | 加密+解锁         | 需输入「当前密码」(旧口令证明),全部条目重加密,作废旧票据 |
| 免密登录时长(滑块)             | 任意              | 0 = 每次;1–30 天;-1 = 永远(均仅本机)                     |

状态机:

```text
             set-password                    (restart)            unlock
  plain ──────────────────► encrypted+unlocked ──────► encrypted+locked ──► unlocked
    ▲                            │  ▲                                        │
    └──── 外部明文替换(重加密/拒绝) ──┘  └──────────── change-password ───────────┘
```

- **锁定期间**:web 服务照常;继承环境凭证仍可解析,文件凭证抛 `VAULT_LOCKED`;设置页即解锁入口
- **免密窗口**:票据签发时写入 `issuedAt` 与 `days`;滑块改动立即作废旧票据并(解锁态)按新时长重签;打开 WebUI 自动尝试免密解锁
- **忘记密码**:不可恢复(设计如此);删除 `.credentials.yaml` 后,设置页仍要求先建立新密码,随后才能重新配置凭证

## 凭证解析顺序

| 优先级 | 来源                                | 说明                                        |
| :----- | :---------------------------------- | :------------------------------------------ |
| 1      | 继承环境(launching environment)     | 只读、高于受管文件;对其遮蔽的引用写入被拒绝 |
| 2      | 受管文件 `.credentials.yaml`        | 明文或密文形态,可写                         |
| 3      | `.env` 回退(project-env / user-env) | 低于受管文件,仅在文件无此引用时兜底         |

`allowEnvFallback: false` 可关闭第 1、3 层(严格仅文件策略)。

## 磁盘格式

**明文形态**(未设密码,与 `dsh-credentials-local` 完全一致):

```yaml
OPENCODE_GO_API_KEY: sk-…
```

**密文形态**(设密码后,同一文件内容被替换):

```json
{
  "format": "dsh-encrypt-credentials",
  "version": 3,
  "algorithm": "aes-256-gcm+sha3-256",
  "kdf": "argon2id",
  "kdfInput": "sha3-256-password",
  "m": 65536,
  "t": 3,
  "p": 1,
  "salt": "<base64url>",
  "verifier": { "data": "<base64url>", "sha3": "<hex>" },
  "remember": {
    "salt": "<base64url>",
    "issuedAt": 1755000000000,
    "days": 7,
    "cipher": { "data": "<base64url>", "sha3": "<hex>" }
  },
  "entries": { "OPENCODE_GO_API_KEY": { "data": "<base64url>", "sha3": "<hex>" } },
  "sha3": "<document fingerprint>"
}
```

- 主密钥 = Argon2id(密码的 SHA3-256 摘要, salt, m/t/p);原始密码不进后端
- v2 scrypt 密文仍可解析与解锁,成功解锁时自动原地升级为 v3 Argon2id
- `verifier` 是固定明文的 AEAD 密文,用于在不接触任何真实凭证的前提下校验摘要
- `remember` 块仅在签发过免密票据时存在:`cipher` 是票据密钥 AEAD 包裹的主密钥,版本、盐、签发时间和期限均绑定到 GCM 认证;票据本身只在浏览器 Cookie(HttpOnly),永不落盘;`days: -1` 表示永远
- 文档级指纹覆盖 `sha3` 以外全部字段;条目级指纹覆盖各自密文 blob;成本参数有上限(防恶意构造耗尽内存/CPU)
- 密码与票据从不落盘

## HTTP 路由(web 行)

仅 `POST application/json`(与官方 /api 相同的跨站写护栏),全部路由在读取请求体前先过 **Host 头信任围栏**(防 DNS rebinding):Host 必须解析为回环主机名或命中 `trustedHosts`,否则 **403 `FORBIDDEN_HOST`**;解锁、改密、设密和免密设置进一步**限制为本机**(Host 回环 **且** socket 回环,不给 `trustedHosts` 例外)。请求体上限 4 KiB,读取时限 10 秒。响应 `{ ok: true, value }` 或 `{ ok: false, code, message }`,错误消息不含密码或任何密钥材料:

| 路径                               | 请求体                                                  | 作用                                                                                                                |
| :--------------------------------- | :------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------ |
| `/api/credentials.status`          | `{}`                                                    | 状态快照;本机且携带免密票据(Cookie;header 通道下也接受 `x-dsh-encrypt-remember`)时先尝试票据解锁                    |
| `/api/credentials.unlock`          | `{ digest }`                                            | 密码摘要解锁(**仅本机**);成功后再按滑块签发免密票据(HttpOnly Cookie;header 通道才随响应体回传票据);失败过多返回 429 |
| `/api/credentials.set-password`    | `{ digest }`                                            | 明文 → 密文(**仅本机**),写入密文策略标记                                                                            |
| `/api/credentials.change-password` | `{ oldDigest, digest }`                                 | 重加密(**已解锁 + 证明当前口令**,仅本机;作废旧票据并签发新票)                                                       |
| `/api/credentials.config`          | `{ action: "get" }` / `{ action: "set", rememberDays }` | 读取状态 / 设置免密天数(set 仅本机)                                                                                 |

`rememberChannel: "header"` 可显式切回响应体回传 + localStorage + 请求头通道(XSS 可读票据,仅用于 Cookie 存取异常的 WebView);默认 Cookie 通道下,响应体永不携带票据,旧 localStorage 副本自动清理作废。headless 组合不挂载 web 行,无 HTTP 面。

## 配置项

provider 行 `config`:

| 字段                                                   | 类型             | 默认值                        | 说明                                                                             |
| :----------------------------------------------------- | :--------------- | :---------------------------- | :------------------------------------------------------------------------------- |
| `path`                                                 | string           | `$DSH_HOME/.credentials.yaml` | 凭证文件绝对路径                                                                 |
| `dshHome`                                              | string           | 运行时注入                    | Harness home                                                                     |
| `allowEnvFallback`                                     | boolean          | `true`                        | 启用继承环境与 `.env` 回退层                                                     |
| `passwordEnv`                                          | string           | `DSH_CREDENTIAL_PASSWORD`     | 启动自动解锁的环境变量名                                                         |
| `watch` / `debounceMs`                                 | boolean / number | `true` / `100`                | 热重载与防抖                                                                     |
| `rememberDays`                                         | number           | `0`                           | 免密天数:-1 永远;0 每次;1–30 天(运行时值写入 `$DSH_HOME/.dsh-encrypt.json` 优先) |
| `rememberChannel`                                      | string           | `"cookie"`                    | 免密票据通道:cookie(默认)/ header(兼容通道)                                      |
| `leakGuard`                                            | boolean          | `true`                        | 凭证泄露检测与输出脱敏总开关                                                     |
| `leakMinMaskLength` / `leakMaxMaskLength`              | number           | `8` / `256`                   | 脱敏长度窗口(4–64 / 16–1024)                                                     |
| `maxUnlockAttempts` / `lockoutBaseMs` / `lockoutMaxMs` | number           | `5` / `30000` / `900000`      | 解锁爆破锁定阈值与指数退避参数                                                   |

web 行 `config`:

| 字段           | 类型     | 默认值 | 说明                                                                                 |
| :------------- | :------- | :----- | :----------------------------------------------------------------------------------- |
| `trustedHosts` | string[] | `[]`   | 除回环外只放行状态读取和配置读取的权威来源(host 或 host:port);该配置不会放行密码操作 |

## 安全模型

**保证**:

- 静态存储只含密文;内存快照在密文形态下只保存密文记录
- 每条目随机 12 字节 nonce;引用名作为 GCM AAD,换位认证失败
- 双层 SHA3-256 指纹 + GCM 认证标签:篡改且重算指纹仍以 `VAULT_KEY_MISMATCH` 失败(与错误主密钥不可区分——AEAD 的诚实答案)
- 密码经 Argon2id 派生,只存盐与 AEAD 验证器;文档成本参数有上限
- 阅后即焚 + 按请求解密 + 密钥锁定/卸载清零
- 永远密文:设密后无法回退明文
- POSIX 上凭证文件必须由当前用户拥有且权限为 0600,父目录不得由其他用户写入;读取拒绝符号链接和非普通文件
- 防爆破:失败计数持久化 + 指数退避 + 429/`Retry-After`;密码派生串行执行,待处理请求数量受限
- 防注入回显(Leak Guard):解析过的凭证在 HTTP 文本响应与 WS 文本消息离开主机前被替换为 `[REDACTED:dsh-encrypt]`;过滤器覆盖 HTTP 分块边界、运行中新增的凭证值和 WS continuation 分帧
- 防 DNS rebinding(Host 围栏)与防 LAN 伪造回环(Host+socket 双重判定)
- 改密需证明当前口令(`oldDigest`),且与解锁共用锁定计数(锁定窗口期间改密同样 429 拒绝)
- 发行文件一致性检查会拒绝缺失、多出、越界或哈希不一致的构建文件
- 防版本漂移:运行时兼容护栏(跨线 `UNSUPPORTED_DSH`,同线 rc 漂移警告)

**诚实边界**:

- JS 字符串不可变,解密明文无法在内存中清零——给出的保证是**不持久化、不缓存、不进日志**,操作结束即丢弃引用
- 解锁期间主密钥必须驻留内存,请以操作系统账户 + 0600 文件保护
- 忘记密码不可恢复;唯一恢复手段是清除凭证文件后重新配置
- 完整性清单不是信任根:能改写插件目录的攻击者也能重新生成清单;真正的信任根是用户密码
- 锁定计数存于状态文件,同一 OS 用户可编辑重置——锁定防的是在线猜密码,防不了同账户自我解锁
- 脱敏只覆盖本插件已知的值;模型把密钥经工具调用(bash/web_search/网络)外传不属输出脱敏覆盖范围;拆分/转码可绕过子串匹配
- **服务端无法校验密码强度**:后端只见摘要,「至少 8 个字符」仅由 WebUI 前端强制;直连 API 可设置任意弱口令,摘要即口令,请自行保证强度
- 摘要即口令等价物:捕获一次即可解锁直到改密;密码操作只接受本机请求,`trustedHosts` 不会扩大该范围
- `rememberChannel: "header"` 的票据对页面脚本可读(XSS 可窃取);默认 Cookie 通道无此暴露面
- 锁定计数为全局:任何能到达解锁接口的客户端故意输错即可反向锁定合法用户(DoS),属在线猜口令防御的固有代价
- 仅本机操作的“本机”判定依赖 Host+socket:非浏览器进程仍可伪造两者,但那已是你本机可执行的任意代码等价物——护栏防的是浏览器/局域网,不是同主机恶意进程

## 错误码

| code                                                               | 含义                                                            |
| :----------------------------------------------------------------- | :-------------------------------------------------------------- |
| `PASSWORD_WRONG` / `PASSWORD_INVALID`                              | 摘要与验证器不匹配 / 摘要不是 64 位小写 hex                     |
| `LOCAL_ONLY`                                                       | 该操作(改密/设密/免密设置/票据签发)仅允许本机(Host+socket 回环) |
| `FORBIDDEN_HOST`                                                   | Host 非受信来源(HTTP 403)                                       |
| `REMEMBER_EXPIRED` / `REMEMBER_INVALID`                            | 免密票据超窗 / 与本凭证库不匹配                                 |
| `VAULT_LOCKED` / `VAULT_NOT_ENCRYPTED` / `VAULT_ALREADY_ENCRYPTED` | 锁定 / 未设密 / 已设密                                          |
| `VAULT_CORRUPTED` / `VAULT_INVALID` / `VAULT_KEY_MISMATCH`         | 完整性校验失败 / 结构非法 / 主密钥不匹配或密文被替换            |
| `TOO_MANY_ATTEMPTS`                                                | 解锁失败过多,进入锁定窗口(HTTP 429 + `Retry-After`)             |
| `INTEGRITY_FAILED`                                                 | 发行代码完整性校验失败(拒绝加载;合法重建后 `pnpm build`)        |
| `UNSUPPORTED_DSH`                                                  | 运行中 dsh 版本超出插件支持线(拒绝加载;见部署架构升级 SOP)      |

## 部署架构:dshenv 运行时与系统分离

dsh-encrypt 与 dsh 运行时解耦到三层,**dsh 更新不再影响插件安装与加载**:

| 层     | 位置                                                                                               | 更新方式                                          |
| :----- | :------------------------------------------------------------------------------------------------- | :------------------------------------------------ |
| 运行时 | `D:\Developments\DSH\dshenv`(package.json 精确钉 `@deepseek-ai/dsh@0.1.0-rc.7`,无 `^`)             | 显式编辑版本号 + 重装 + 重链 + 冒烟(见 SOP)       |
| 系统   | `$DSH_HOME\profiles`(195 个 @deepseek-ai junction 指向 dshenv + 锁文件)                            | 仅当 dshenv 更新时重跑 `dshenv\link-profiles.ps1` |
| 插件   | `D:\Developments\DSH\DSH-Encrypt`(源码 + 自持依赖树 + 自己的 pnpm-lock.yaml,junction 挂进 profile) | 与 dsh 完全无关,独立开发/发布                     |

要点:

- 运行时不再活在 npx 缓存:`npm cache clean` 不会破坏 profile
- 插件依赖树自持且接缝包精确钉版(与运行时同线);独立包保持范围
- 兼容护栏(fail-loud):跨线 `UNSUPPORTED_DSH`,同线 rc 漂移警告——绝不静默失效
- 支持矩阵:dsh-encrypt rc.12 ↔ dsh `0.1.0-rc.7` 线 ↔ 接缝 rc.6/4.0.1(当前实测组合)

**启动姿势(npx 仍兼容)**:

| 姿势                                  | 说明                                                                               |
| :------------------------------------ | :--------------------------------------------------------------------------------- |
| `dshenv\dsh.cmd web`                  | 不碰 npx,最稳(推荐)                                                                |
| `npx @deepseek-ai/dsh@0.1.0-rc.7 web` | 同样的 npx 手癖、显式钉版,永不漂移                                                 |
| `npx @deepseek-ai/dsh web`(裸命令)    | 当前可用(npx 缓存即 rc.7,已验证);缓存被清后可能拉最新——由兼容护栏明确报错/警告兜底 |

**升级 dsh 的 SOP(唯一允许的变更路径)**:

1. 编辑 `dshenv\package.json` 版本号 → `npm install`;
2. `cd DSH-Encrypt && pnpm test`(42 项)确认插件不受影响;
3. `powershell -File dshenv\link-profiles.ps1 -ProfilesRoot "C:\Users\Yu\.dsh\profiles"`(e2e-home 同理);
4. `dsh --profile web --dump-config` 冒烟(确认 dsh-encrypt 行在);
5. 重启。若报 `UNSUPPORTED_DSH`:版本线不兼容,回退 dshenv 版本或先升级插件。

**回滚 SOP**:`dshenv\package.json` 改回 `0.1.0-rc.7` → `npm install` → 重跑 link-profiles.ps1 → 重启。

## 卸载与回滚

密文策略下没有「移除密码」路径,文件永为密文;基础 `credentials` 行读不懂密文文档,因此卸载前**先备份并删除凭证文件**(或接受重新录入):

1. 备份/删除 `$DSH_HOME/.credentials.yaml` 与 `.dsh-encrypt.json`;
2. 删除 `$DSH_HOME/profiles/web/cordis.patch.yml` 中的 `dsh-encrypt-web` insert;
3. `dsh plugin --profile web remove dsh-encrypt`(headless 同理)。

基础 `credentials` 行随 bundle 移除自动恢复启用。源码 junction 安装时,「移除」= 移除 junction + 删除 package.json 里的 `link:` 依赖。

## 开发与测试

```sh
corepack enable
pnpm install --frozen-lockfile # 自包含依赖树;接缝包精确钉版
pnpm check                 # 格式、lint、TypeScript、Vitest、Knip 全量检查
pnpm test                  # Vitest 回归测试;pretest 自动执行 tsdown 构建与完整性清单
pnpm build                 # 构建并自动重建 lib/integrity-manifest.json
pnpm pack                  # prepack 自动重建清单后打包
```

源码使用 TypeScript 7,由 tsdown 生成 ESM、类型声明和 source map;格式化与 lint 配置来自 `@mzwing/oxc-config`。

安全测试覆盖密码解锁与并发锁定、密文文件缺失、登录票据期限认证、文件符号链接、请求结构校验、字面量最长匹配、HTTP 分块过滤、WebSocket continuation 分帧、完整性清单覆盖、运行时兼容检查和浏览器 SHA3。

浏览器包 ModuleLoader/SSR 冒烟已包含在 Vitest 套件中。

测试套件仅本地回归用,不随 npm 包分发(`files` 仅含 `lib` 与 `cordis.patch.yml`)。

## 版本历史(简)

- **0.1.0-rc.6 → rc.8**:KDF 输入改为密码摘要;永久密文策略;免密票据通道;阅后即焚
- **rc.9**:scrypt → Argon2id(v3);解锁爆破锁定;泄露检测与输出脱敏;完整性自校验
- **rc.10**:修复完整性自校验对行尾敏感的 bug(哈希前归一化 + .gitattributes)
- **rc.11**:Host 头信任围栏(防 DNS rebinding);票据默认仅 HttpOnly Cookie;改密必须 oldDigest
- **rc.12**:输出脱敏真正接线(并修复一次性响应体被吞的缺陷);改密受锁定窗口约束;本机判定升级为 Host+socket 双重;请求体上限与内部错误脱敏;运行时兼容护栏(UNSUPPORTED_DSH);与 dsh 三层解耦(dshenv)

## 许可证

[MIT](./LICENSE) · © 2026 Yauntyours
