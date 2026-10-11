<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# 更新日志

本文件记录本 crate 的显著变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-10-11

一次深度安全评审后的版本，核心是**密钥分离**。密文格式换代到 `0x03`/`0x04`，
但**双读**：1.2.x 写出的旧密文无需任何操作即可照读。

### 安全

- **密钥分离（HKDF-SHA256）。** DB 路径的确定性 ECB 对任意明文块给出
  `E_K(块)`，本质上是一台加密预言机 —— 而此前的 README 与测试都教用户两条
  路径共用同一把主密钥。那会让**能往 DB 侧列写入可控值**的攻击者借它取得
  GCM 的 keystream（命中行约前 2 KB 明文）与 GHASH 子密钥 H（16 个 NUL 即可，
  无条件），机密性与完整性同时失守。现在主密钥只做派生：应用侧与 DB 侧各拿
  一把互不可推的子密钥（`info` 分别为 `encryptable-rust/aead/v1` 与
  `encryptable-rust/db-ecb/v1`）。「两条路径配同一把主密钥」从**危险**变为
  **推荐**。金标量由 Python `cryptography` 独立复算、openssl 交叉验证。
- **上下文绑定。** 新增 `seal_with_context` / `decrypt_with_context` /
  `decrypt_text_with_context` / `rotate_to_current_key_with_context`（`Guard`
  同名转发）：上下文进 AAD，把密文钉死在「哪一行/哪一列」上，防「把别人的
  密文粘到自己行上」。此前 AAD 只有版本字节，跨行跨列的密文移植**照样过认证**。
- **DB 解密错误文案折叠。** 补位长度非法、补位字节不自洽、结果不是合法 UTF-8
  曾各有可区分的消息 —— 在攻击者能触发解密的场景里就是一个 padding oracle
  （逐字节改密文看错误分类，可还原 `D_K(·)`）。现在折叠成一条，与「密钥错」
  也不可区分，与应用侧 tag 校验失败的做法一致。

### 修复

- **`DbEncrypter::encrypt` 不再永久误拒 `AQ`/`AR`/`AS`/`AT` 开头的合法明文。**
  首字节恒为 `0x01` 由前两个 base64 字符唯一决定，因此 24 字符及以上的此类
  业务码（订单号、券码、SKU）此前**每次**被拒，且 DB 侧没有绕过口。现在形状
  闸带长度前置（真应用侧载荷 base64 后恒 ≥ 40 字符），并新增
  `DbEncrypter::seal()` 作为显式绕过口。
- **`decrypt_or_original` 不再返回类型名。** `Value::Int(42)` 曾经解出 `"int"` ——
  既不是原值也不是原输入，是静默的数据损坏。现在按 `Display` 渲染（`"42"`，
  `Null` → 空串）。
- **AES-128 的 hex 密钥可以解析了。** hex 分支此前写死 64 字符：AES-128 的
  `to_hex()` 输出（32 字符）喂回解析器会被当成 32 字节字面量拒绝。现在按
  「密码要求长度的两倍」判定。
- **`EnvConfig::from_env()` 的 panic 文案修正并补 `## Panics` 文档** ——
  此前在 `ENCRYPTION_PREVIOUS_KEYS` 写成 JSON 时 panic，消息却写着
  「未设置时不可能失败」，与事实相反。
- **`DbEncrypter::new` 在配置带 `previous_keys` 时向 stderr 打警告**：DB 路径
  没有密钥环，照应用侧剧本轮换会让 SQL 一侧静默变 NULL（MySQL）或报错
  （pgcrypto）。此前只有 README 里一句「已知上限」。
- **CLI**：移除空操作的 `--raw`（帮助文本曾列出它）；管道输入 trim 全部尾随
  空白（修 Windows 风格 `\r` 残留导致解密静默失败），不再 `Box::leak`；
  `--driver` 严格校验且只对 `sql` 命令有效；无参数时用法说明改走 stderr
  （stdout 留给正常输出）；`keygen` 的 hex 拼装单次分配。
- **warp 的 pet 过滤器补 `path::end()`**：`/pet.svg/anything` 不再被吞，
  与其余七个适配器的精确路径一致。

### 变更（行为收紧）

- 新密文一律 `0x03`（应用侧）/ `0x04`（DB 侧）；`0x01`/`0x02` 旧格式**只读**，
  `rotate_to_current_key()` 会把旧格式一并搬成 `0x03`。`is_encrypted` 两代都认。
- `decrypt_expr` 产出按格式字节分派的 CASE 表达式，两代密钥都内嵌 —— 迁移期
  的混合列一条语句全读；旧数据搬完后可改用只含子密钥（`derived_key_hex()`）
  的手写语句，把主密钥从 SQL 里拿掉。
- `pet::data_uri()` 返回 `&'static str`（`LazyLock` 静态化，README 示例中它是
  每请求路径，此前每次重编码 4.7 KB）；新增 `pet::DATA_URI` 常量。
- `Value` 的 `Debug` 遮蔽字符串载荷（`decrypt()` 的返回值最容易被
  `tracing::debug!(?v)` 随手记录，而它是明文 PII）；`ArrayConfig` / `EnvConfig`
  的密钥字段 `Zeroizing` 化、`Debug` 手写遮蔽 —— 此前 `dbg!(config)` 会直接
  打印主密钥。
- **`Error` 与 `Cipher` 标注 `#[non_exhaustive]`**：下游穷尽 `match` 需要补
  `_` 分支。趁 1.x 早期收紧，之后再补代价只增不减。

### 性能

- 形状判定的长度前置（短于真载荷最短 base64 字符数的输入免解码再判）：
  DB 写路径实测 ~-33%、应用侧 ~-4%；顺带缓解「为看一个字节全量解码」的
  大输入放大。判据是必要条件，不会漏判任何真密文 —— 语义不变。
- `pet::data_uri()` 编码只做一次。

### 测试

- 新增 `tests/cli.rs`：子进程级契约（keygen→encrypt→decrypt 往返、退出码
  0/1/2、管道输入与尾随空白、`--driver` 严格性、SQL 命令的 stdout/stderr 分工）。
- 新增：上下文绑定（含错误上下文、跨路径拒绝、轮换保持绑定）；旧格式 `0x01`
  载荷的手工构造与双读；「当前格式用子密钥而非主密钥」的源码级断言（两侧）；
  并发 nonce 唯一性（8 线程 × 200）；1 MiB 往返；DB 忽略 `previous_keys` 钉死；
  AES-128 金标量；`AQ` 前缀误拒回归。
- 金标量换代：`0x04` 向量由 Python `cryptography` + openssl 独立复算；
  原 `0x02` OpenSSL 向量转为**双读回归锚**（只断言解密，不再断言加密输出）。

### 文档

- README（中英）：载荷格式表、新增「密钥分离」一节、SQL 片段为 CASE 形态、
  上下文绑定用法、CLI 提示、已知上限逐条同步；修掉框架集成安装示例的
  `version = "0.1"`（crates.io 从无此版本，照抄会直接解析失败）。

### CI / 发布

- clippy 与 doc 改 `--all-features`：八个集成模块此前从未被 lint / 断链检查 ——
  1.2.1 修的那批框架文档示例错误正是被 feature 门挡在 CI 外的类型。
- 全部 cargo 命令加 `--locked`（lock 已提交：有 bin 且 MSRV job 靠它钉版本）；
  package job 去掉 `--allow-dirty`。MSRV job 加 `--all-features`。
- `actions/checkout` v4 → v7；新增 `dependabot.yml`（cargo + actions，每周）
  与每周的 `cargo audit` 工作流（加密库的 RUSTSEC 公告不该靠人记得）。
- `Cargo.toml` 补 `[package.metadata.docs.rs] all-features = true` —— 此前
  docs.rs 上八个集成模块与 serde API 完全不可见。

### 依赖

- 新增 `hkdf` 0.12 与 `sha2` 0.10（用途子密钥派生 —— 安全原语不手写）。

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

[1.3.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.3.0
[1.2.1]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.2.1
[1.2.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.2.0
[1.1.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.1.0
[1.0.0]: https://github.com/erikwang2013/encryptable-rust/releases/tag/v1.0.0
