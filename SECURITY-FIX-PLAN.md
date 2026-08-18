# DSH-Encrypt rc.11 安全修复计划（已批准执行）

## 实施记录（rc.11 已完成）

- F1 ✅ `lib/trust.js` 新增；`web.js` 全部路由接入 Host 围栏（403 FORBIDDEN_HOST），改密/票据/免密设置钉死回环 Host；web 行新增 `Config.trustedHosts` 与 0.0.0.0 绑定告警
- F3 ✅ `vault.js` 新增 `verifyPasswordDigest`；`index.js changePassword(oldDigest, digest)` 先验证器校验（错误计入锁定，成功清零）；web 路由与 client 表单（「当前密码」）接入
- F2 ✅ `rememberChannel` 配置（默认 cookie）；响应体仅在 header 模式回传 ticket；cookie 模式忽略 header 票据（旧 localStorage 副本作废）；client 侧清理遗留键
- F5 ✅ 文档修正：clear-password 注释移除、LOCAL_ONLY 措辞、FORBIDDEN_HOST 错误码、锁定 DoS 与摘要等价物诚实边界、升级说明
- 测试 ✅ 63/63（新增 trust.test.js、web.test.js；vault/provider 测试更新至 digest 协议；e2e-webui.mjs 更新至 digest+oldDigest+无移除路径）
- 验证 ✅ `npm test` 全绿、client-smoke 通过、`npm pack` 产物含 `lib/trust.js`（version 0.1.0-rc.11）

未决/后续：PAKE（OPAQUE）留待 rc.12+ 评估；LAN 部署需在 `dsh-encrypt-web` 行配置 `trustedHosts`。

## 部署与自检（本机实际环境，2026-08-18）

### 部署现状

- 本机用「源码目录安装」：`C:\Users\Yu\.dsh\profiles\node_modules\dsh-encrypt` 与 `C:\Users\Yu\.dsh\profiles\web\node_modules\dsh-encrypt` 均为指向 `D:\Developments\DSH\DSH-Encrypt` 的 junction —— 源码改动即已位于安装位置，**无需重新 `dsh plugin add`**；完整性清单已随 pretest/prepack 重建，重启不会触发 `INTEGRITY_FAILED`。
- 仅存在 web profile（无 headless）。
- profile 用户层（`C:\Users\Yu\.dsh\profiles\web\cordis.patch.yml`）：`dsh-encrypt-web` 行已配置 `inject: [webRuntime]` + `trustedHosts: !!js '[...ctx.webRuntime.trustedHosts, "frp-ski.com:57262"]'`（行级 inject 与官方 `connection` 行同款写法，否则加载器解析 `!!js` 时抛 `cannot get property "webRuntime" without inject`）；`dsh-encrypt` provider 行与 `connection` 行未改动。
- 当前运行中的实例仍是 rc.10 旧代码（实测 `Host: evil.com:3080` 返回 200 + `local: true`），**必须重启 `dsh web` 生效；重启会中断承载中的会话**。

### 重启后自检（Windows，curl.exe）

```powershell
# 1) rebinding 回归：应 403 + FORBIDDEN_HOST（旧代码这里是 200）
curl.exe -s -m 10 -w "`nHTTP:%{http_code}`n" -X POST http://127.0.0.1:3080/api/credentials.status -H "Content-Type: application/json" -H "Host: evil.com:3080" -d "{}"

# 2) 本机正常：应 200 + ok:true
curl.exe -s -m 10 -w "`nHTTP:%{http_code}`n" -X POST http://127.0.0.1:3080/api/credentials.status -H "Content-Type: application/json" -d "{}"

# 3) frp 隧道域名可远程 status/unlock（trustedHosts 放行）：应 200
curl.exe -s -m 10 -w "`nHTTP:%{http_code}`n" -X POST http://127.0.0.1:3080/api/credentials.status -H "Content-Type: application/json" -H "Host: frp-ski.com:57262" -d "{}"

# 4) 隧道域名改密仍被拒（设计钉死本机）：应 400 + LOCAL_ONLY（只读探测，安全）
curl.exe -s -m 10 -w "`nHTTP:%{http_code}`n" -X POST http://127.0.0.1:3080/api/credentials.set-password -H "Content-Type: application/json" -H "Host: frp-ski.com:57262" -d '{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
```

### 重启后预期行为

| 访问来源 | status / unlock | set-password / change-password / config-set |
| :-- | :-- | :-- |
| 本机浏览器（localhost / 127.0.0.1） | ✅ | ✅（改密需输「当前密码」） |
| frp 隧道外部浏览器（trustedHosts） | ✅（需输密码解锁） | ❌ 403/`LOCAL_ONLY` |
| 其他域名 / DNS rebinding 页面 | ❌ 403 `FORBIDDEN_HOST` | ❌ |

另注意：解锁响应体不再含 `ticket` 字段（cookie 模式）；旧 localStorage 票据升级即作废并自动清理，用户可能需要重新解锁一次。

### 回滚

- 票据通道回旧：provider 行 config 加 `rememberChannel: "header"`。
- 关闭远程解锁：删除 `dsh-encrypt-web` 行的 `trustedHosts`（回环访问不受影响）。

批准记录：F2 默认 cookie-only ✅ · F3 改密强制旧口令 ✅ · F5 unlock 加 Host 围栏 ✅ · PAKE 延后（rc.12+ 评估）。

## F1 — Host 头护栏（根修，DNS rebinding）
- 新增 lib/trust.js：isLoopbackHostname（localhost/[::1]/127-8）、parseAuthority、canonicalAuthority、assertTrustedAuthority、isTrustedRequest(req, trustedHosts)（Host + Sec-Fetch-Site + Origin）、isLoopbackRequest = isTrustedRequest(req, [])。语义对齐核心 dsh-client-connection isTrustedApiRequest。
- web.js：isLocalRequest 改为 Host 版（保留导出名）；web 行新增 Config { trustedHosts: z.array(String).default([]) } 并导出；status/unlock/config-get 过 isTrustedRequest(req, trustedHosts)，不通过 403 FORBIDDEN_HOST；set-password/change-password/config-set/票据签发/票据消费钉死 isLoopbackRequest（与核心 PRIVILEGED_METHODS 对齐，不给 trustedHosts 例外）；webServer.host === "0.0.0.0" 时启动告警。

## F3 — change-password 旧口令校验
- vault.js：新增导出 verifyPasswordDigest(text, digest)（derive + verifier 校验 + zeroize，失败 PASSWORD_WRONG）。
- index.js：changePassword(oldDigest, digest)，校验两参 isDigest；transition 回调内（锁内、reconcile 后）重新 assertUnlocked 并 verifyPasswordDigest(this.text, oldDigest)，失败 recordUnlockFailure + 抛出；成功后 clearUnlockFailures。
- web.js：change-password 路由请求体 { digest, oldDigest }。client.js：改密卡片加「当前密码」输入框，发送 oldDigest。

## F2 — 票据通道收敛
- index.js Config 增加 rememberChannel: "cookie" | "header"，默认 "cookie"；status() 快照携带 rememberChannel。
- web.js：四个路由响应体仅在 channel === "header" 时携带 ticket；status 路由在 cookie 模式下忽略 header 票据（只读 cookie）——旧 localStorage 副本即告作废。
- client.js：删除默认 localStorage 读写；syncTicket 仅 header 模式生效；cookie 模式下清理遗留 dsh-encrypt-remember。

## F5 — 附带修正
- web.js 头部注释删除过期的 clear-password 路由条目。
- README：LOCAL_ONLY 措辞去「移除密码」；诚实边界补「摘要=口令等价物、明文 HTTP 传输、LAN 需 TLS 代理」；补「攻击者故意输错可反向锁定合法用户（DoS）」；错误码表加 FORBIDDEN_HOST；升级说明 rc.10→rc.11。
- 票据读取（readRememberHeader/Cookie）仅在 isLoopbackRequest 时消费。

## 测试
- test/vault.test.js、test/provider.test.js 风格对齐；新增 trust 单元、web 路由 rebinding（remoteAddress=127.0.0.1 + Host: evil.com）、403 FORBIDDEN_HOST、cookie 模式无 ticket 键、header 通道忽略、changePassword 新旧摘要用例。
- test/e2e-webui.mjs 修正：过期的 { password } 改为 { digest }；phase 2 去掉 clear-password（改为断言 404）；change-password 带 oldDigest。

## 发布（rc.11）
- version 0.1.0-rc.11；npm run integrity（pretest/prepack 自动）；npm test；npm pack（files 含 lib/trust.js）；双 profile 重装；README 升级章节。

## rc.12 复查修复（2026-08-18 安全复查，已执行）

复查确认 F1/F2/F3/F5 均已正确落实（trust 边界实证、依赖 audit 0 漏洞、63/63 通过），并发现以下残留问题，全部修复：

- **H1（高危）输出脱敏从未接线**：`installLeakRedaction` 只有定义没有调用（git 全历史确认），凭证回显不会被替换。修复：`web.apply()` 在路由注册前通过 `ctx.effect` 安装 HTTP/WS 脱敏代理；顺带修复 `redactingHttpHandler` 的 `res.end(chunk)` 先 flush 后 push 导致一次性响应体被吞的缺陷（接线测试暴露）。补 `test/leak-guard.test.js`（字面量转义/最长优先/流式分块边界/WS 帧过滤/拆分帧/二进制直通）+ `test/web.test.js` 接线测试（注册前后均被包裹、明文不外泄、dispose 还原、空守卫 passthrough）。
- **M1（中危）change-password 绕过锁定窗口**：改密错误旧口令只计数不拒绝，锁定期间仍是无限猜口令面。修复：`changePassword` 入口与队列内各加 `assertUnlockAllowed()`，锁定期间返回 `TOO_MANY_ATTEMPTS`。补 provider 测试（5 次错误解锁锁定后，环境变量自动解锁的进程改密被拒）。
- **M2（中危）LAN 伪造回环 Host 可接管明文库**：`isLocalRequest` 升级为 Host 回环 **且** socket 回环（新增 `trust.isLoopbackSocket`，覆盖 127.0.0.1/::1/::ffff:127.0.0.1 映射）。改密/设密/免密设置与票据签发消费全部收紧；0.0.0.0 绑定 + 明文库时启动告警。补 trust/web 测试。
- **L1**：请求体上限 64 KiB（413 payload-too-large），补测试。
- **L2**：锁定态下把免密窗口调成 0 不再因缺密钥报错；新增 `revokeRememberIfDisabled` 在下次密码/票据解锁后撤销旧块。补 provider 测试。
- **L3**：服务端只见摘要、无法校验密码强度——README 诚实边界补充说明（≥8 位仅 WebUI 前端约束）。
- **L4**：非 VaultError 的 message 不再回传（logger 留痕 + 通用 500 internal），杜绝路径泄露。补测试。
- **L5**：README 版本表/安装示例/测试数量（84）与安全测试覆盖清单对齐实现，升级章节补 rc.11→rc.12；新增 `test/lockout.test.js`（阈值/指数退避/上限/不复位）。

验证：`npm test` 84/84 通过；`npm run integrity` 重建清单（lib/index.js、lib/trust.js、lib/web.js 哈希已更新）；`npm pack` 产出 dsh-encrypt-0.1.0-rc.12.tgz。

部署：本机 profile 为源码 junction，重启 `dsh web` 即生效（无需重新 `dsh plugin add`）。
