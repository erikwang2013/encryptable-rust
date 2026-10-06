<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# 更新日志

本文件记录本 crate 的显著变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-07

首个正式版本。Rust 移植自 PHP 包 [`erikwang2013/encryptable`](https://github.com/erikwang2013/encryptable)。

### 新增

**两条加密路径**

- `AeadEncrypter` —— 应用侧，AES-256-GCM（或 AES-128-GCM），随机 nonce，带认证 tag。
  载荷 `base64( 0x01 ‖ nonce(12) ‖ 密文 ‖ tag(16) )`，版本字节作 AAD。
- `DbEncrypter` —— DB 侧，AES-256-ECB（或 AES-128-ECB），确定性，手写 PKCS#7 补位。
  载荷 `base64( 0x02 ‖ AES-ECB-PKCS7(明文) )`，无类型信封（SQL 要看到逐字节原值）。
- 两条路径各带格式字节，交叉使用会得到明确的 `Error::WrongFormat` 而不是静默二次加密。

**密钥管理**

- `Key`：构造时按密码校验长度，绝不截断或补零；支持字面量、64 位 hex、`base64:` 前缀三种写法；
  内部用 `Zeroizing` 包裹，`Debug` 输出遮蔽密钥内容。
- `KeyRing`：主密钥 + 退役密钥，去重保序。
- `AeadEncrypter::rotate_to_current_key()`：读旧密钥、写新密钥，支持零停机密钥轮换。
- `PreviousKeysParser`：逗号分隔解析；JSON 数组**显式拒绝**（按逗号硬拆会得到两把错的密钥）。

**类型信封**

- `Value`：`Null` / `String` / `Int(i64)` / `Float(f64)` / `Bool`，编码为 `tag(1B) ‖ 载荷`。
- 载荷长度与类型字节严格吻合，多余字节即报错 —— 不存在 PHP `settype()` 那种静默转换。

**DB 方言 SQL 片段**

- MySQL：`CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(col), 2 ), UNHEX('<hex>') ) USING 'UTF8' )`
- PostgreSQL：`convert_from( decrypt( substring( decode(col, 'base64') from 2 ), '\x<hex>'::bytea, 'aes-ecb' ), 'UTF8' )`
- 列名过白名单（注入防护）；密钥以 hex 嵌入，片段内不含任何 `'` 转义。

**配置**

- `ArrayConfig`（代码给配置）/ `EnvConfig`（读 `ENCRYPTION_KEY` · `ENCRYPTION_CIPHER` ·
  `ENCRYPTION_PREVIOUS_KEYS` · `ENCRYPTION_DB_DRIVER`）。
- `EnvConfig::from_env_with()`：注入式取值，测试无需改动进程环境（Rust 2024 中 `set_env` 是 `unsafe`）。

**框架集成**（各一个 opt-in feature，默认构建一个都不拉）

- 请求守卫 `Guard`（`Arc` 共享，`Send + Sync`）与 `Guarded` trait。
- axum · actix-web · rocket · poem · salvo · warp · bee-rust · e-cat。
- bee-rust 与 e-cat 都建在 axum 0.8 之上，复用同一适配层。
- 提取失败统一翻译为 500（装配错误），加解密失败由调用方处置。

**其它**

- CLI `encryptable`：`keygen` · `encrypt` · `decrypt` · `rotate` · `db-encrypt` ·
  `db-decrypt` · `sql` · `pet`。
- 可选 `serde` feature：`encrypt_json` / `decrypt_json`。
- 项目宠物 **Locky · 小锁灵**：`docs/pet.svg` 经 `include_str!` 内联进 crate。

### 与 PHP 版的差异

- **不做字节级互通**（刻意）：信封重新设计，去掉手工 HMAC、`crypt:` 脏位与非 AEAD 分支。
  PHP 写的密文 Rust 读不了，反之亦然；已有列需在应用侧重加密迁移。
- **配置可照抄**：`ENCRYPTION_*` 变量名、密码名、列名写法一致。

### 依赖

运行时只有 4 个：`aes-gcm` · `aes` · `zeroize` · `base64`。

[1.0.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.0.0
