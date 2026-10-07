<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# 更新日志

本文件记录本 crate 的显著变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.2.1] - 2026-10-07

一次审计后的内部优化。**没有 API 变化，没有密码学行为变化** —— 1.2.0 产生的
密文与 1.2.1 完全互通，升级不需要重新加密任何数据。

### 性能

- **解密不再重建 AES 密钥调度。** 原本密钥环循环里对每一把钥匙调一次
  `Aes256Gcm::new_from_slice`，包括本来就已建好的主密钥 —— 单密钥部署下等于
  每请求白算一遍密钥调度，外加两次 `Box` 分配。现在整环的 cipher 在**构造时**
  一次建好，解密只剩 AEAD 解封本身。
- **`encrypt()` 先做廉价的形状判定再决定要不要认证。** 原本对每个字符串都直接
  试一次完整 AEAD 解封；明文通常根本不是合法 base64，到形状判定就被挡掉。
  两阶段保留了原有的正确性：形状像密文的**明文**（base64 解出来首字节恰好是
  `0x01`）仍会被正确地加密，不会被误判成密文存进去。
- **DB 侧解密少两次堆分配。** 原本 `decoded[1..].to_vec()` 再
  `plain.to_vec()`；现在就地跳过版本字节、就地截掉 PKCS#7 补位，
  `String::from_utf8` 直接接管同一个缓冲。

### 依赖

- **去掉两个声明了却一行都没引用的可选依赖：`bee_router` 与 `ecat-middleware`。**
  两个适配层实际只用 axum（e-cat 另需 tower / http 两个 trait 来源）。
  实测依赖树：`bee-rust` feature **171 → 90 个 crate**，`ecat` **118 → 90 个**。
- 去掉 `zeroize` 的 `zeroize_derive` feature —— 本 crate 没有一处
  `derive(Zeroize)`，用到的只有 `Zeroizing` 包装类型。

### 修复

- **六个框架集成模块的文档示例根本编译不过**，一直没被发现。`actix` / `rocket` /
  `poem` / `warp` / `ecat` / `salvo` 的模块级示例里写的是
  `let guard = /* … */;` —— `/* … */` 是块注释，那行实际是 `let guard = ;`，
  语法错误。这些示例都挂在 feature 后面，而此前的 feature 验证跑的是
  `cargo test --features X --lib`，**`--lib` 不跑文档测试**，于是六处一起漏了过去。
  现在示例改为真正构造一个守卫，顺带把 `poem`（少 `use EndpointExt`）与
  `salvo`（示例引用了非默认 feature 才有的 `affix_state`）两处一并修正。
  新增的 CI 跑的是不带 `--lib` 的 `cargo test --features X`，这类问题以后会在
  推送时就被挡住。

### 文档

- 补齐 **23 处**`# Errors` 文档段落（clippy `missing_errors_doc` 从 23 条降到 0）。
  逐个写明会返回哪些 `Error` 变体、什么条件下返回 —— 对 docs.rs 上的读者来说
  这是最先要看的一段。
- `KeyRing::is_empty()` 补上准确文档：它**恒为 `false`**（环按构造至少含主密钥），
  并点明「守卫配没配密钥」该看 `len() == 1` 而不是它。
- `DbEncrypter::decrypt` 的文档里写明：**密钥错时 ECB 不保证报错** ——
  没有认证就没有可靠的判据，这是 ECB 的固有性质，不是实现缺陷。

### 新增

- **CI**（`.github/workflows/ci.yml`）：fmt · clippy（`-D warnings`）· 默认与 serde 测试 ·
  **MSRV 1.88 实机验证**（`Cargo.toml` 声明的版本得真的能编）· 每个 feature 一个
  矩阵 job · `cargo publish --dry-run` 打包验证。此前推送没有任何自动检查。

## [1.2.0] - 2026-10-07

宠物再往前一步：从「库里有这个 API」变成「框架里挂上就有」，并把四张图里的抽象图形换成真实形象。

### 新增

- **每个框架适配层的内置图标处理器** —— 挂上即有 `Content-Type: image/svg+xml` 的项目图标：
  `integrations::axum::pet` · `integrations::actix::pet` · `integrations::rocket::pet`
  （自带 `#[get("/pet.svg")]`）· `integrations::poem::pet` ·
  `integrations::salvo::pet` · `integrations::warp::pet`（已绑 `/pet.svg` 路径）。
  bee-rust 与 e-cat 复用 axum 的那一个。
- `integrations::salvo::write_pet(&mut Response)` —— 不依赖 salvo 处理器机制的裸写入版本。
- `pet::CONTENT_TYPE` —— `image/svg+xml`。

### 变更

- 四张图示（架构 / 功能 / 请求周期 / 生命周期，中英各一）里的抽象图形换成**真实的
  `docs/pet.svg` 形象**：`lifecycle.svg` 第三条泳道原本手绘的钥匙环改为真宠物，
  其余三张加了角落形象。
- CLI 报错时附上宠物 —— **仅在交互式终端**（`stderr` 是 TTY 时）。脚本与 CI
  把 stderr 重定向进日志的场景不会多出七行 ASCII。
- 新增 `docs/social-preview.png`（1280×640）与它的可编辑源文件
  `docs/social-preview.svg`，在 GitHub 仓库设置里作为社交预览图上传。
  两者都加进了 Cargo 的 `exclude` —— 纯仓库资产，不该让下游下载。

### 说明

本版**无破坏性变更**。按语义化版本，新增公开 API 属次要版本，故为 1.2.0。

## [1.1.0] - 2026-10-07

把项目宠物从「文档里的图」变成 crate 的正式一部分，并修掉英文文档里的几处不自然。

### 新增

- `pet::svg()` —— 原始 SVG 标记（对应常量 `pet::SVG`）。
- `pet::ascii()` —— 终端等宽版（对应常量 `pet::ASCII`）。
- `pet::data_uri()` —— `data:image/svg+xml;base64,…`，可直接塞进 HTML 的 `<img src>`。
  下游因此不必依赖本库的文件布局：形象经 `include_str!` 打进二进制，与 `SVG` 是同一份。
- `pet::SVG_LEN` —— 形象的字节数。
- CLI 新增 `--version` / `-V`：输出 `encryptable <版本>`，附宠物与座右铭。
- CLI 的 `--help` 与无参数调用现在都会先打印宠物。

### 变更

- 两份 README 语言切换行里的 🌐 换成项目宠物图标。
- 英文 README 里 3 处包裹英文标签的全角括号 `【】` 改为加粗。
- crate 文档补上宠物 API 的可运行示例。

### 说明

本版**无破坏性变更**，也没有改密码学行为 —— 1.0.0 产生的密文与 1.1.0 完全互通。
按语义化版本，新增公开 API 属次要版本，故为 1.1.0 而非 1.0.1。

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

[1.2.1]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.2.1
[1.2.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.2.0
[1.1.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.1.0
[1.0.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.0.0
