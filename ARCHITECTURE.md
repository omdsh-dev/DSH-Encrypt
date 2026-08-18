# dsh-encrypt 架构

本项目使用分层模块承载加密凭证生命周期，并保留 `src/index.ts`、`src/vault.ts`、`src/web.ts`、`src/client.ts` 作为兼容入口。兼容入口负责组合与导出，不再承载可复用的底层规则。

## 模块边界

| 层       | 目录                 | 职责                                                   | 允许依赖                  |
| :------- | :------------------- | :----------------------------------------------------- | :------------------------ |
| 领域     | `src/domain`         | 常量、稳定错误码、文档和 Provider 类型、Valibot schema | `src/shared`、Valibot     |
| 应用     | `src/application`    | 密码转换、记住登录、串行操作、状态视图策略             | 领域层、基础设施端口实现  |
| 基础设施 | `src/infrastructure` | Node 密码学、磁盘文档、权限、运行时配置                | 领域层、共享校验          |
| 传输     | `src/transport`      | HTTP 结构类型、请求 schema、限量读取和边界错误         | 领域层、共享校验、Valibot |
| 安全     | `src/security`       | 字面量泄露匹配、HTTP 与 WebSocket 脱敏                 | LeakGuard 的窄接口        |
| 客户端   | `src/client`         | 浏览器 SHA3、API、票据存储、界面状态映射               | 浏览器标准 API            |
| 共享     | `src/shared`         | 无状态、无平台依赖的字符和文本校验                     | 无项目内依赖              |

依赖方向以领域类型为中心。密码学模块不读取文件，文档模块不处理 HTTP，HTTP schema 不调用 Provider，客户端不导入 Node API。

## Vault 组合

`src/vault.ts` 维持原有包导出。实际实现由以下模块组成：

1. `domain/vault/model.ts` 定义文档常量、类型和 `VaultError`。
2. `domain/vault/schemas.ts` 用 Valibot 校验持久化文档。
3. `infrastructure/crypto/vault-crypto.ts` 处理 Argon2id、scrypt、AES-GCM、SHA3 和密钥清零。
4. `infrastructure/persistence/vault-document.ts` 处理规范化序列化、结构校验和文档指纹。
5. `application/password-service.ts` 处理设密、解锁和密码证明。
6. `application/remember-service.ts` 处理票据签发、有效期和主密钥恢复。

每个模块都可以通过内存输入单独测试。磁盘文档格式、公开函数名和稳定错误码由兼容入口保持。

## 校验策略

项目使用两类校验：

- Valibot 校验 JSON、状态文件和 HTTP 请求等不可信结构。
- 显式字符扫描校验十六进制、凭证引用和版本文本。

项目不使用正则表达式。泄露检测使用不可变字面量 trie，并按“最早位置、最长值、互不重叠”选择匹配项。该实现不会把凭证内容拼进动态正则，也不会受到正则特殊字符影响。

`@deepseek-ai/schemastery` 只保留在 Cordis 的静态插件配置边界，因为该边界由宿主框架读取。业务输入和磁盘输入统一由 Valibot 校验。

## 并发与状态

`OperationQueue` 为文件修改提供失败隔离的串行顺序。Provider 的任务失败不会污染队列尾部，后续任务仍可运行。密码解锁入口限制待处理请求数量，已接收的请求再进入同一串行队列执行状态变更。

`src/web.ts` 只组合路由、访问检查和应用操作。共享 HTTP 结构及限量请求读取位于传输层；HTTP 与 WebSocket 输出脱敏位于安全层。

运行时状态文件按字段独立校验。一个损坏字段不会抹掉同文件内其他有效字段。Provider 只把加密记录保存在长期快照中；明文只存在于一次解析或回调期间。

## 变更规则

- 新磁盘字段必须先加入领域类型和 Valibot schema，再加入规范化指纹字段顺序。
- 新 HTTP 操作必须先定义精确请求 schema，禁止使用字符串强制转换接受错误类型。
- 新密码学能力必须留在 `infrastructure/crypto`，并通过领域类型返回结果。
- 新输出通道必须复用安全模块的字面量脱敏器，或明确记录无法扫描的二进制边界。
- 兼容入口的导出变更必须配套声明构建和回归测试。
