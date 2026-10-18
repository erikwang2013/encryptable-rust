<!-- Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz -->

# encryptable-rust

<img src="./docs/pet.svg" alt="Locky · 小锁灵 —— 项目宠物" width="26"> **简体中文（本页）** · [English](./docs/i18n/en/README.md)

为敏感字段提供「可检索的匿名化 / 加密」能力：写入数据库前加密，读出时解密，并可生成与 MySQL / PostgreSQL 兼容的 SQL 片段。用两条路径把「落库加密」与「按原值查询」这对通常不可兼得的需求分开处理 —— 应用侧 AES-256-GCM（随机 nonce、带认证，**默认选它**），DB 侧 AES-256-ECB（确定性，只给必须在 `WHERE` 里按原值比对的列）。两条路径各由 HKDF 从主密钥派生**自己的子密钥**，互不触碰 —— 理由见[密钥分离](#密钥分离为什么-db-侧不能直接用主密钥)。

项目宠物 **Locky · 小锁灵**（[`docs/pet.svg`](./docs/pet.svg)）—— 钥匙环上那把琥珀色的是当前主密钥，两把灰色的是 `previous_keys`。

框架集成覆盖 **axum · actix-web · rocket · poem · salvo · warp · [bee-rust](https://github.com/erikwang2013/bee-rust) · [e-cat](https://github.com/erikwang2013/e-cat)**，全部 opt-in，默认构建一个都不拉。

---

## 项目宠物：Locky · 小锁灵

<img src="./docs/pet.svg" alt="Locky · 小锁灵 —— encryptable-rust 项目宠物" width="340">

一只挂着钥匙环的锁灵。人设不是装饰，是把本库的密钥模型画出来了：

| 形象 | 对应设计 |
|------|---------|
| 环上居中的琥珀色钥匙 | **当前主密钥**。新密文一律用它产生（`KeyRing::primary()`） |
| 两把灰色钥匙（各旋开 30°） | `previous_keys` —— 还在环上、还能解开旧密文，直到你主动退役 |
| 钥匙环本身 | `KeyRing`：主密钥在前、退役密钥在后，解密时按顺序逐个试，任一把成功即可 |
| 锁扣上的 AEAD 徽章 | 应用侧 AES-GCM 的认证 tag：解不开就是密钥不对或密文被改，没有第三种解释 |
| 铭牌 `Locky · 小锁灵` | 宠物名（`pet::NAME`） |

座右铭：**钥匙还在环上，旧密文就还解得开。**

形象以 `include_str!` 打进库里（[`src/pet.rs`](./src/pet.rs)，零运行时开销，不用就不链接），`pet::ASCII` 直接在终端或日志里打：

```rust
use encryptable::pet;

println!("{}", pet::ASCII);

//          .--.
//         /    \        Locky · 小锁灵
//        _|    |_
//       |        |      琥珀钥匙 = 主密钥
//       |  o  o  |      两把灰钥匙 = previous_keys
//       |    ^   |      锁扣 = AEAD tag
//       |________|
```

形象是 crate 的正式一部分，不是文档附件。四个常量与四个函数对外公开，README、CLI banner、下游管理界面共用同一份：

| API | 返回 | 用途 |
|-----|------|------|
| `pet::NAME` / `pet::TAGLINE` | 名称与座右铭 | 界面文案 |
| `pet::ASCII` / `pet::ascii()` | 等宽版形象 | 终端、日志、CLI banner |
| `pet::SVG` / `pet::svg()` | 原始 SVG 标记 | README、管理后台 |
| `pet::data_uri()` | `data:image/svg+xml;base64,…` | 直接塞进 HTML 的 `<img src>` |
| `pet::SVG_LEN` | 字节数 | 需要预留缓冲区时 |

`data_uri()` 是给下游用的：它和 `SVG` 是同一份 `include_str!` 的结果，所以调用方**不必依赖本库的文件布局**——形象一定在二进制里。挂一个图标端点：

```rust
use axum::response::Html;

async fn pet_icon() -> Html<String> {
    Html(format!(
        r#"<img src="{}" alt="Locky" width="64">"#,
        encryptable::pet::data_uri()
    ))
}
```

命令行里也有：`encryptable pet` 打印形象，`encryptable --version` 与 `--help` 都会带上它。CLI 报错时也会附上宠物，**但只在交互式终端里**——脚本与 CI 把 stderr 重定向进日志时不会多出七行 ASCII。

#### 内置的图标端点

每个框架适配层都带一个现成的处理器，挂上就有 `Content-Type: image/svg+xml` 的项目图标，不用自己写：

```rust
// axum（bee-rust 与 e-cat 也用这个，它们都在 axum 之上）
Router::new().route("/pet.svg", get(encryptable::integrations::axum::pet))

// actix-web
App::new().route("/pet.svg", web::get().to(encryptable::integrations::actix::pet))

// rocket
rocket::build().mount("/", routes![encryptable::integrations::rocket::pet])

// poem
Route::new().at("/pet.svg", get(encryptable::integrations::poem::pet))

// salvo
Router::new().get(encryptable::integrations::salvo::pet)

// warp
encryptable::integrations::warp::pet()      // 已绑好 /pet.svg 路径
```

salvo 另有一个 `write_pet(&mut Response)`，不依赖它的处理器机制，任何拿得到 `&mut Response` 的地方都能用。

`Content-Type` 是这个端点唯一容易做错的地方：少了它浏览器会把 SVG 当纯文本渲染，用户看到的是一屏 XML 而不是那只挂钥匙环的锁——所以每个适配层的测试都盯着这个头。

`docs/pet.svg` **不能**进 Cargo 的 `exclude` —— `include_str!` 在编译期读它，排掉就当场编译失败（`cargo package` 会直接报错，不会静默漏发）。

---


<!-- pet-expressions:start -->
## 项目宠物表情形态 · Locky

<table align="center">
<tr><td align="center"><img src="docs/pet-expressions/smile.svg" width="88" alt="笑"><br><b>笑</b><br><code>:emoji-smile:</code></td><td align="center"><img src="docs/pet-expressions/joy.svg" width="88" alt="欢乐"><br><b>欢乐</b><br><code>:emoji-joy:</code></td><td align="center"><img src="docs/pet-expressions/cry.svg" width="88" alt="哭"><br><b>哭</b><br><code>:emoji-cry:</code></td><td align="center"><img src="docs/pet-expressions/depressed.svg" width="88" alt="沮丧"><br><b>沮丧</b><br><code>:emoji-depressed:</code></td><td align="center"><img src="docs/pet-expressions/terrified.svg" width="88" alt="惊恐"><br><b>惊恐</b><br><code>:emoji-terrified:</code></td><td align="center"><img src="docs/pet-expressions/angry.svg" width="88" alt="愤怒"><br><b>愤怒</b><br><code>:emoji-angry:</code></td></tr>
<tr><td align="center"><img src="docs/pet-expressions/coquettish.svg" width="88" alt="撒娇"><br><b>撒娇</b><br><code>:emoji-coquettish:</code></td><td align="center"><img src="docs/pet-expressions/cute.svg" width="88" alt="卖萌"><br><b>卖萌</b><br><code>:emoji-cute:</code></td><td align="center"><img src="docs/pet-expressions/pleasing.svg" width="88" alt="讨好"><br><b>讨好</b><br><code>:emoji-pleasing:</code></td><td align="center"><img src="docs/pet-expressions/knocking.svg" width="88" alt="敲打"><br><b>敲打</b><br><code>:emoji-knocking:</code></td><td align="center"><img src="docs/pet-expressions/facepalm.svg" width="88" alt="捂脸"><br><b>捂脸</b><br><code>:emoji-facepalm:</code></td><td align="center"><img src="docs/pet-expressions/tongue.svg" width="88" alt="吐舌头"><br><b>吐舌头</b><br><code>:emoji-tongue:</code></td></tr>
</table>

> 12 种彩色动态形态：笑 / 欢乐 / 哭 / 沮丧 / 惊恐 / 愤怒 / 撒娇 / 卖萌 / 讨好 / 敲打 / 捂脸 / 吐舌头。每个 SVG 自带表情、情绪特效与整体动效，并遵循 `prefers-reduced-motion`。
<!-- pet-expressions:end -->

<!-- assets-license:start -->
## 视觉资产授权 / Visual Assets License

本项目的项目宠物、图片、图标、表情（包括 `docs/pet-expressions/` 等目录下的
SVG / PNG）**不是开源资产**，版权归作者所有。未经书面许可不得复制、修改、再分发或
用于商业用途；商业使用需取得商业授权，联系 **erik@erik.xyz**。详见
[ASSETS-LICENSE.md](ASSETS-LICENSE.md)。

> 代码部分仍遵循仓库原有 `LICENSE`；第三方素材（如明确标注的 Go Gopher 等）仍遵循其原许可证。
<!-- assets-license:end -->


## 项目目录

```
encryptable-rust/
├── src/
│   ├── lib.rs                 crate 文档、模块导出、两条路径的对照表
│   ├── cipher.rs              密码白名单（6 个）与三条性质：is_aead / is_deterministic / key_len
│   ├── key.rs                 Key（零化 + 长度校验 + 遮蔽 Debug）与 KeyRing（主密钥 + 退役密钥）
│   ├── serializer.rs          类型信封 Value：tag(1B) || 载荷
│   ├── error.rs               Error 枚举（13 个变体）与 Result
│   ├── pet.rs                 项目宠物形象（NAME · TAGLINE · ASCII · SVG + svg()/ascii()/data_uri()）
│   ├── guard.rs               请求守卫 Guard：跨请求共享的加密句柄（Arc 共享，Send+Sync）
│   ├── serde_support.rs       可选集成：encrypt_json / decrypt_json（--features serde）
│   ├── config/                EncryptableConfig trait + DbDriver 方言
│   │                          ArrayConfig（代码给配置）/ EnvConfig（读 ENCRYPTION_*）
│   ├── encrypter/             两条路径的导出 + 格式字节不变量
│   │   ├── aead/mod.rs        应用侧信封·密钥环·HKDF 子密钥·上下文绑定·轮换
│   │   ├── aead/tests.rs      应用侧的单元测试（拆分以守住单文件 500 行上限）
│   │   ├── db/mod.rs          PKCS#7 + ECB·HKDF 子密钥·SQL 片段·列名白名单
│   │   └── db/tests.rs        DB 侧的单元测试（含与 OpenSSL 对齐的金标量）
│   ├── integrations/         框架适配层：Guarded trait + 每个框架一个模块
│   │                          mod.rs（Guarded · GuardNotConfigured）、axum.rs、
│   │                          actix.rs、rocket.rs、poem.rs、salvo.rs、warp.rs、
│   │                          ecat.rs（tower 层）；bee_rust 复用 axum
│   ├── support/
│   │   ├── previous_keys.rs  逗号分隔的退役密钥解析（JSON 数组显式拒绝）
│   │   └── subkeys.rs        HKDF-SHA256 用途子密钥派生（内部设施）
│   └── bin/encryptable.rs     CLI：8 个命令，手写参数解析，不引 clap
├── tests/
│   ├── cli.rs                CLI 子进程契约：命令往返、退出码 0/1/2、管道输入
│   ├── db_sql.rs              SQL 片段逐字符钉死、列名注入防护、绑定查询的稳定性
│   ├── invariants.rs          跨模块不变量：往返、篡改、确定性、两种载荷互不通用
│   └── rotation.rs            密钥轮换的整条零停机迁移路径
├── examples/quickstart.rs     两条路径 + 一次完整轮换的可运行演示
├── docs/
│   ├── pet.svg                项目宠物（被 src/pet.rs 用 include_str! 内联，勿加进 exclude）
│   ├── diagrams/zh-CN/        中文版图示：architecture · features · request-lifecycle · lifecycle
│   ├── diagrams/en/           英文版同名图示
│   ├── i18n/en/README.md      English README
│   ├── social-preview.png     1280×640 社交预览图（仓库设置里上传，不进 crate 包）
│   ├── social-preview.svg     它的可编辑源文件
│   ├── alipay.png             打赏码
│   └── weixinpay.png          打赏码
├── .github/workflows/ci.yml   CI：fmt · clippy · test · MSRV 1.88 · 每个 feature 一个矩阵 job · 打包
├── .github/workflows/audit.yml  每周 cargo audit（RUSTSEC 公告）
└── Cargo.toml                 默认依赖只有 aes-gcm / aes / hkdf / sha2 / zeroize / base64
```

---

## 设计思路

### 为什么是「可检索的加密」

落库加密（不是哈希、不是脱敏）与「按原值查询」通常不可兼得：带随机 nonce 的认证加密每次产出不同密文，`WHERE phone = ?` 永远匹配不上。纯加密库要你自己写持久层，ORM 方案把你锁进一个框架。这个库用两条路径把两头补上，而不是把一条路径拧成妥协：

| | 应用侧 `AeadEncrypter` | DB 侧 `DbEncrypter` |
|---|---|---|
| 密码 | AES-256-GCM（认证） | AES-256-ECB（确定性） |
| 密文 | 随机 nonce，同明文两次不同 | 同明文恒定相同 |
| 用途 | **默认**，所有存储场景 | 必须在 `WHERE` 里按原值比对的列 |
| 风险 | 无 | 频率分析可行，低基数列出卖隐私 |

DB 路径只能用 ECB 不是历史包袱，是数据库能力的硬边界：MySQL 的 `AES_DECRYPT` 与 pgcrypto 的 `decrypt` 都只认 ECB/CBC，**没有 GCM**。要让数据库自己解密，就别无选择。

两条路径产出的载荷**不兼容**，各自带格式字节（应用侧当前 `0x03`、旧一代 `0x01`；DB 侧当前 `0x04`、旧一代 `0x02`）。解密拿错格式会得到明确的 `Error::WrongFormat`；**DB 侧加密**也会拦下应用侧载荷（带长度闸，短输入不误伤；绕过口是 `DbEncrypter::seal`）。反方向的**应用侧加密**没有免费断言（ECB 无认证，形状判定又有假阳性上限，拦了会误伤形状恰好吻合的明文）—— 别把 DB 侧密文喂进 `AeadEncrypter::encrypt`，这条差异是刻意的。

### 密钥分离：为什么 DB 侧不能直接用主密钥

DB 侧的确定性 ECB 对任意明文块给出 `E_K(块)` —— 它本质上是**一台加密预言机**。如果它和 AES-GCM 共用同一把主密钥 K，攻击者就能借它取得 `E_K(nonce ‖ 计数器)`（GCM 的数据 keystream 与 tag 掩码）、乃至 `E_K(0^128)`（GHASH 子密钥 H），机密性与完整性同时失守 —— 「GCM 的密钥必须专用」是 NIST SP 800-57 的老要求。

所以主密钥只做一件事：派生。两条路径各拿一把互不可推的子密钥：

```text
子密钥 = HKDF-SHA256(ikm = 主密钥, salt = 空, info = 用途串, L = 密码的密钥长度)
应用侧用途串："encryptable-rust/aead/v1"
DB  侧用途串："encryptable-rust/db-ecb/v1"
```

于是「两条路径配同一把主密钥」是安全的、也是推荐的部署方式。派生是确定性的：`openssl kdf`、Python 的 `cryptography` 都能独立复算 —— 本库的金标量就是这么交叉验证的（见「开发」一节）。

### 架构原则

- **每条路径自己声明能收什么密码** —— 应用侧只收 AEAD（无认证的密文被篡改时会静默产出垃圾），DB 侧只收确定性 ECB（否则等值查询永远匹配不上）。判定在**构造时**：配错了就在启动时炸，而不是等到某个深夜的请求路径上才失败。
- **配置是一个 trait，不是一张全局表** —— `EncryptableConfig` 只有四个方法（`key` / `cipher` / `previous_keys` / `db_driver`），后三个有默认实现，所以最小实现只需覆写 `key()`。`ArrayConfig` 与 `EnvConfig` 是它的两个实现，没有容器、没有回调、没有第三级回退。
- **读配置是一次快照，不是活视图** —— 加密器在构造时把环境变量读成自有字段，之后进程里再改环境也不影响已建好的加密器。这既好预期，也顺带避开了「读值读到一半被别人改了」的竞态。
- **密钥长度在构造时定死** —— 不截断、不补零。补零会把弱口令直接当密钥用（主密钥不做口令拉伸，见「已知上限」）；截断会让轮换后仍落在相同的前缀密钥上，运维以为换过了其实没换。
- **用途子密钥在构造时派生** —— 主密钥经 HKDF-SHA256 派生两条路径各自的子密钥（见「密钥分离」），密钥环上每一把钥匙都各派生各的。
- **密钥在内存里套 `Zeroizing`，`Debug` 手写遮蔽** —— `Key`、`ArrayConfig`、`EnvConfig`、`Guard` 的 `format!("…{x:?}")` 只会打印字节数或占位符，任何一句 `dbg!` 或错误信息都漏不出主密钥。`Value` 的 `Debug` 同样遮蔽字符串载荷（它承载的是明文）。
- **失败不静默** —— 解不开就报错，不做「失败返回原文」的兜底：那是明文被悄悄写进加密列的主要途径。确实需要的话用 `decrypt_or_original`，让这个决定显式出现在调用点。DB 路径的 `previous_keys` 被忽略时也会向 stderr 打一条警告，而不是让你某天发现 SQL 一侧全是 NULL。
- **类型对不上就报错，不猜** —— 二进制类型信封，`int` 载荷必须正好 8 字节，多一个字节也报错；类型与载荷不符也不会被静默转换（`"abc"` 不会变成 `0`），而是 `Error::Unserialize`。
- **`#![forbid(unsafe_code)]`** —— 整个 crate 没有一行 `unsafe`。
- **不为几十行的事加依赖** —— 手写 `Display` 而不引 `thiserror`；手写 PKCS#7 + ECB 而不引 `ecb` crate；手写列名白名单而不引 `regex`；CLI 手写参数解析而不引 `clap`。唯一的例外是安全原语：HKDF 用 `hkdf` + `sha2`，密码学不手写。

### 权衡

| 决策 | 选择 | 理由 |
|------|------|------|
| ECB vs CBC（DB 侧） | ECB | 确定性是等值查询的前提；CBC 的 IV 每次不同，`WHERE` 比对不上，SQL 片段也解不了 |
| 主密钥 vs 用途子密钥 | 子密钥（HKDF-SHA256） | DB 侧 ECB 对任意块给出 `E_K(块)`，是加密预言机；与 GCM 共用主密钥会同时拆掉机密性与完整性（NIST SP 800-57：GCM 密钥必须专用） |
| 格式换代 vs 原地改语义 | 新版本字节 `0x03`/`0x04` + 双读 | 升级不动旧密文，写新读旧；`rotate_to_current_key()` 逐步搬迁后才退役旧格式 |
| 确定性 vs 语义安全 | 只在 DB 侧确定性 | 应用侧保持随机 nonce 的语义安全；确定性是「按原值查询」的入场费，只在必须的列上付 |
| 二进制信封 vs 文本信封 | 二进制 | 文本信封会把 `integer:"abc"` 静默变 `0`；二进制信封类型对不上就直接报错 |
| GCM tag vs 手工 HMAC | GCM tag | 给 DB 侧密文压 32 字节 HMAC 前缀，只为让 SQL 用 `SUBSTRING(..., 33)` 剥掉它 —— 而 DB 侧从不校验，纯属占位；那 32 字节让给版本字节，SQL 只需 `SUBSTRING(..., 2)` |
| 手写 ECB vs 引 `ecb` crate | 手写 | `ecb` 0.2 走 cipher 0.5，与 `aes-gcm` 0.10 的 cipher 0.4 不兼容，引进来会拖入第二套 AES 栈 |
| 严格解密 vs 宽松回退 | 严格 | 宽松回退是明文被悄悄写进库的主要途径；宽松版降级成显式的 `decrypt_or_original` |
| 密钥走 hex vs 走带引号字符串 | hex | SQL 片段里因此不含任何 `'`，转义漏一个字符导致注入的可能性也就不存在了 —— 片段里只剩 `'UTF8'` / `'base64'` / `'aes-ecb'` 三个固定常量 |
| `ENCRYPTION_PREVIOUS_KEYS` 收 JSON 数组 | 拒绝 | `["k1","k2"]` 按逗号硬拆会得到两把**错的**密钥，而错密钥在密钥环里静默失效 —— 解密跳过它继续试，最后只报一句「全都失败」，没人看得出真因是配置格式。宁可在读配置时就炸 |

---

## 设计架构

![架构设计：处理器 → 框架集成层 → 请求守卫 → 两条加密路径 → 支撑模块 → 数据库](./docs/diagrams/zh-CN/architecture.svg)

两端共用一份配置（`EncryptableConfig` 的 `ArrayConfig` / `EnvConfig` 两个实现），配置在**构造时**就被解析进加密器，之后不再读环境、不再解析字符串。各模块的职责见「项目目录」里的树注释。

自下而上读这张图：支撑模块（密钥环、类型信封、密码白名单、配置、错误）被两条加密路径共用；两条路径各有自己的格式字节，中间那道隔断是刻意的 —— 把一方的密文喂给另一方会得到明确的 `Error::WrongFormat`，而不是静默二次加密。框架集成层只在最上面薄薄一层，它的全部工作是把 `Guard` 交到处理器手里。

### 载荷格式

这是全文最该记住的一张表：

| | 布局（版本字节两代并存，**新写入一律是当前一代**） | 类型信封 | AAD |
|---|---|---|---|
| 应用侧 当前 `0x03` | `base64( 0x03 \|\| nonce(12B) \|\| AES-GCM 密文 \|\| tag(16B) )` | 有：`tag(1B) \|\| 载荷` | 版本字节 [‖ 上下文] |
| 应用侧 旧 `0x01` | 同上，首字节 `0x01`，主密钥直用（1.2.x，**只读**） | 同上 | 版本字节 |
| DB 侧 当前 `0x04` | `base64( 0x04 \|\| AES-ECB-PKCS7(明文) )` | **无** | 无 |
| DB 侧 旧 `0x02` | 同上，首字节 `0x02`，主密钥直用（1.2.x，**只读**） | **无** | 无 |

版本字节之上还有一层**密钥**换代：当前一代用 HKDF 派生的用途子密钥（见上一节），旧一代是主密钥直用，双读保留。1.2.x 写出的旧密文**无需任何操作**即可照读；用 `rotate_to_current_key()`（或 CLI 的 `rotate`）逐步搬成 `0x03` 后，主密钥才彻底不再接触密文。DB 侧的旧列同理：搬成 `0x04` 后可以换成只含子密钥的 SQL 语句，把主密钥从 SQL 里拿掉。

类型信封的字节定义（应用侧）：tag 1 字节 + 定长载荷 —— `0x00` 无载荷（`Null`）、`0x01` UTF-8 字节（`String`）、`0x02` i64 小端 8 字节（`Int`）、`0x03` f64 小端 8 字节（`Float`）、`0x04` 单字节 0/1（`Bool`）。载荷长度与类型字节必须**严格**吻合，多一个字节也报错。

DB 侧不带类型信封是刻意的：SQL 要看到**逐字节的原值**，套一层类型字节会让库里躺着的明文带上信封头，`WHERE` 比对也就对不上了。

---

## 实现功能

![功能设计：两条加密路径、SQL 片段、密钥轮换、类型信封、框架集成、CLI、项目宠物](./docs/diagrams/zh-CN/features.svg)

### 应用侧：`AeadEncrypter`（默认选它）

| 方法 | 作用 |
|------|------|
| `new(&config)` | 构造时校验密码是 AEAD、密钥长度符合、退役密钥与主密钥等长，并派生子密钥 |
| `encrypt(value)` | 加密一个值；已经是本格式（任何一代）的密文则**原样返回**。判定方式是试着解开它，不是看形状。绑定过上下文的密文别往这里喂 |
| `seal(value)` | 无条件加密，不做「是否已是密文」的判定 |
| `seal_with_context(ctx, value)` | 绑定上下文加密：上下文进 AAD，把密文钉死在「哪一行/哪一列」上，防「把别人的密文粘到自己行上」 |
| `decrypt(payload)` | 解密成 `Value`；密钥环上任一把钥匙成功即可 |
| `decrypt_text(payload)` | 解密并断言结果是字符串 |
| `decrypt_with_context(ctx, payload)` / `decrypt_text_with_context` | 解绑定了上下文的密文；上下文对不上就认证失败（这是特性） |
| `decrypt_or_original(payload)` | 宽松版：解不开就原样返回；解出非字符串值时按 `Display` 渲染（`Int(42)` → `"42"`，不再是类型名） |
| `is_encrypted(value)` | 廉价形状判定，不碰密钥、不做认证 |
| `rotate_to_current_key(payload)` / `..._with_context` | 读旧密钥、写新密钥（旧格式 `0x01` 一并搬成 `0x03`）；输入本来就是明文时原样返回 |
| `cipher_name()` / `ring_len()` / `primary_key_hex()` | 诊断用；最后一个是**主密钥**的十六进制表示（`Zeroizing<String>`） |

加密入口接受 `impl Into<Value>`：`&str` / `String` / `i64` / `i32` / `f64` / `bool` / `Option<T>` 都能直接传。`None` 映射到 `Value::Null` —— 注意 **`Null` 会被加密成一段密文**，与「没有值」不是一回事；要不要落 SQL `NULL` 由调用方决定，本库不替你做这个决定。

### DB 侧：`DbEncrypter`

| 方法 | 作用 |
|------|------|
| `new(&config)` | 构造时校验密码是确定性 ECB，并派生子密钥；配置里带 `previous_keys` 会向 stderr 打一条警告（DB 路径没有密钥环） |
| `encrypt(plaintext)` | 确定性加密，产出可直接绑进 `WHERE` 的密文；输入若**看起来**是应用侧载荷（形状 + 长度闸）则报 `Error::WrongFormat` |
| `seal(plaintext)` | 无条件加密 —— 形状判定假阳性上限的绕过口 |
| `decrypt(payload)` | 还原当前（`0x04`）与旧（`0x02`）两种格式（迁移与 CLI 用，**不用于查询**） |
| `decrypt_expr(column, driver)` | 生成让数据库自己解密的 SQL 片段（CASE 按格式字节分派两代密钥，迁移期的混合列一条语句全读） |
| `decrypt_expr_default(column)` | 同上，方言取构造时的配置 |
| `is_encrypted(value)` | 形状判定（两代都认） |
| `key_hex()` / `derived_key_hex()` / `driver()` / `cipher_name()` | 诊断用；前者是主密钥、后者是当前格式（`0x04`）用的子密钥的十六进制表示 |

入参是字符串而不是类型信封 —— 见上一节。

### 配置

`EncryptableConfig` 只有四个方法，后三个有默认值：

| 来源 | 入口 | 说明 |
|------|------|------|
| 代码 | `ArrayConfig::new(key)` | `.with_cipher()` / `.with_previous_keys()` / `.with_db_driver()` |
| 环境 | `EnvConfig::from_env()` | `ENCRYPTION_KEY` / `ENCRYPTION_CIPHER` / `ENCRYPTION_PREVIOUS_KEYS` / `ENCRYPTION_DB_DRIVER`，变量名固定为 `ENCRYPTION_*` 这一套，部署脚本直接沿用 |
| 测试 | `EnvConfig::from_env_with(\|k\| ...)` | 注入取值函数，不碰进程环境 —— Rust 2024 里 `set_var` 是 `unsafe`，且与并发读环境变量的线程存在数据竞争 |

密钥接受的写法：恰好是密码要求长度的字面量、长度恰好为密码要求**两倍**的 hex 字符串（256 位密码 64 字符、128 位 32 字符）、或 `base64:` 前缀。三种写法等价，`encryptable keygen` 会打出其中两种可用写法（hex 与 `base64:` 前缀）—— 裸 base64 不能用，44 个字符按字面量算是 44 字节，长度校验会拒绝它。

### SQL 片段

`decrypt_expr` 产出的 CASE 表达式按格式字节分派两代密钥 —— 迁移期的混合列一条语句全读：

```sql
-- MySQL / MariaDB
CASE SUBSTRING( FROM_BASE64(phone), 1, 1 )
  WHEN 0x04 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('<子密钥 hex>') ) USING 'UTF8' )
  WHEN 0x02 THEN CONVERT( AES_DECRYPT( SUBSTRING( FROM_BASE64(phone), 2 ), UNHEX('<主密钥 hex>') ) USING 'UTF8' )
  ELSE NULL END

-- PostgreSQL (pgcrypto)
CASE get_byte( decode(phone, 'base64'), 0 )
  WHEN 4 THEN convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\x<子密钥 hex>'::bytea, 'aes-ecb' ), 'UTF8' )
  WHEN 2 THEN convert_from( decrypt( substring( decode(phone, 'base64') from 2 ), '\x<主密钥 hex>'::bytea, 'aes-ecb' ), 'UTF8' )
  ELSE NULL END
```

`SUBSTRING(..., 2)` 剥掉的是版本字节。列名先过白名单（首字符字母或下划线，其余字母数字下划线或点，点号必须夹在两段之间），所以片段里不含任何用户可控的字符串。旧数据全部搬成 `0x04` 之后，可以手写只含子密钥（`derived_key_hex()`）的语句，把主密钥从 SQL 里拿掉 —— 在那之前 CASE 的两个分支都需要。

### 可选 serde 集成（`--features serde`）

`encrypt_json<T: Serialize>` 与 `decrypt_json<T: DeserializeOwned>`：任意可序列化类型转成 JSON 后塞进类型信封再加密。JSON 因此躺在**认证过的密文之内**，不需要为它单独设计一套二进制信封；类型对不上（拿 `Vec<i32>` 去读一个 `struct`）报 `Error::Unserialize`，不是乱码。

### CLI 与宠物

8 个命令：`keygen` / `encrypt` / `decrypt` / `rotate` / `db-encrypt` / `db-decrypt` / `sql` / `pet`，用法见「使用说明」。宠物形象走 `encryptable::pet::{NAME, TAGLINE, ASCII, SVG}`。

---

## 框架集成

每个框架一个 opt-in feature，**默认构建一个框架都不拉**。它们做的事都一样：把请求守卫 [`Guard`](./src/guard.rs) 按各框架的惯例交给处理器。

### 请求守卫 `Guard`

`Guard` 是一个 `Arc` 共享的加密句柄，`Clone` + `Send` + `Sync`，构造时就把密钥环解析好，之后每请求零成本：

```rust
use encryptable::config::ArrayConfig;
use encryptable::Guard;

let guard = Guard::new(&ArrayConfig::new("<32 字节密钥>"))?;
// 需要 DB 侧就再挂一个（DB 侧要求确定性密码，所以单独给配置）。
// 主密钥可以直接共用：两条路径各自 HKDF 派生子密钥，共用是安全的、也是推荐做法。
let guard = guard.with_db(&ArrayConfig::new("<同一把密钥>").with_cipher("aes-256-ecb"))?;
```

### `Guarded`：把守卫从一个更大的状态里取出来

真实应用的状态结构体不止一把加密器。实现 `Guarded` 指出守卫在哪个字段，适配层就据此提供各框架的提取器：

```rust
use std::sync::Arc;
use encryptable::Guard;
use encryptable::integrations::Guarded;

#[derive(Clone)]
struct AppState {
    pool: Arc<DbPool>,
    encryption: Guard,          // 守卫是其中一个字段
}

impl Guarded for AppState {
    fn guard(&self) -> &Guard { &self.encryption }
}
```

### 各框架的接入方式

| 框架 | feature | 机制 | 处理器怎么拿 |
|------|---------|------|-------------|
| **axum** 0.8 | `axum` | 实现 `FromRequestParts`，经 `Guarded` 从状态取 | `async fn h(guard: Guard)` |
| **bee-rust** 1.x | `bee-rust` | 路由直接吃 axum handler，**复用 axum 适配层** | `async fn h(guard: Guard)` |
| **actix-web** 4 | `actix-web` | 实现 `FromRequest`，读 `app_data` 里的 `Data<Guard>` | `async fn h(guard: Guard)` |
| **rocket** 0.5 | `rocket` | 实现请求守卫 `FromRequest`，读 `manage` 的托管状态 | `fn h(guard: Guard)` |
| **poem** 3 | `poem` | 实现 `FromRequest`，读 `.data(...)` 注入的扩展 | `async fn h(guard: Guard)` |
| **salvo** 1.0 | `salvo` | 实现 `Extractible`，读 `Depot` | `async fn h(guard: Guard)` |
| **warp** 0.4 | `warp` | 无提取器 trait，提供 `with_guard` 组合子 | `.and(with_guard(g)).map(\|g: Guard\| …)` |
| **e-cat** 4 | `ecat` | 标准 tower `Layer`/`Service`，往请求扩展塞守卫 | `Extension<Guard>` |

```toml
[dependencies]
encryptable-rust = { version = "1", features = ["axum"] }
```

**bee-rust 与 e-cat 都在 axum 0.8 之上**：前者路由直接接收 axum handler（状态也走 axum 的 `State`，所以 `Guarded` 那条路原样可用）；后者 HTTP 传输层是 axum、中间件是 tower，所以 guard 形态就是「往请求扩展里塞一个值」。两处都只需薄薄一层。

### 提取失败一律是 500

`Guarded::guard()` 返回引用，取不到守卫只可能是**装配错误** —— 启动时忘了 `manage` / `app_data` / `with_state` / `data`。用户没做错任何事，所以各适配层统一翻译成 `500` 配一条点明装配步骤的消息（[`GuardNotConfigured`](./src/integrations/mod.rs)），不是 4xx。

加解密**本身**的失败（密钥不对、密文被改）不在这里处理 —— 它发生在处理器体内，由应用决定该回 500 还是 422。本库不替应用做这个决定。

### e-cat 的 tower 层不必装箱

`GuardLayer` 不改写响应与错误，只往请求里塞一个 `Extension`，所以 `type Future = S::Future` 直接透传内层 future，没有 `Pin<Box<dyn ...>>`，也不依赖 `futures`。它与 e-cat 自己的 `ValidateLayer` 是同一形状，可以并排放进同一个 `ServiceBuilder`。

---

## 已知上限

以下几处是**已知且有意保留**的边界。改动前请先读理由 —— 大部分不是待修的缺陷，而是这条路径本身的性质。

### 确定性 ECB 的代价：频率分析可行

同明文恒定产出同密文，这是 DB 路径存在的理由，也是它的代价。低基数列（性别、状态、省份、是否 VIP）加密后**几乎等于没加密** —— 攻击者不需要密钥，数一数密文的出现次数就把分布还原了，剩下的靠常识猜。这条路径只该用在「必须能按原值查询」的列上，其余一律走应用侧。

### `decrypt_expr` 会把密钥嵌进 SQL 文本

片段里的 `UNHEX('<hex>')` / `'\x<hex>'::bytea` 是密钥（迁移期的 CASE 里两代都在：主密钥 + 子密钥），于是它们会进入慢查询日志、`pg_stat_statements`、以及任何记录语句的地方。密钥以 hex 而非带引号字符串的形式进入，至少让「转义漏一个字符导致注入」这条路径不存在 —— 但**泄露本身没有解决**。旧数据搬成 `0x04` 后改用只含子密钥的手写语句，可以把主密钥从 SQL 里拿掉。

推荐做法是别用它做过滤：先用 `encrypt()` 把输入算成密文，再当参数绑定（`WHERE phone = ?`）。既不暴露密钥，又能吃上该列上的索引 —— 用 `decrypt_expr` 包住列名会让索引直接失效。`decrypt_expr` 留给「`SELECT` 列表里要看明文」和报表场景。

### MySQL 的 `block_encryption_mode` 陷阱

MySQL 的 `block_encryption_mode` 会话变量默认是 `aes-128-ecb`，而 `AES_DECRYPT` 走的正是它。用 32 字节密钥时必须先：

```sql
SET block_encryption_mode = 'aes-256-ecb';
```

否则 MySQL 会把 32 字节密钥静默 XOR-fold 成它以为的 16 字节，**返回 NULL 而不报错** —— 你会得到「查询能跑、结果为空」这种最难查的现象。本库挡不住它：密钥长度在构造时就按密码定死，但 `AES_DECRYPT` 用哪个模式是数据库的会话变量说了算，只能在这里点明。

### PG 与 MySQL 的出错行为不同

`convert_from` 遇到非 UTF-8 字节会**直接让整条查询报错中止**；MySQL 的 `CONVERT(... USING 'UTF8')` 则返回 NULL。同一个原因（比如密钥配错了），在两边表现为「查询炸了」与「结果全是 NULL」两种现象。

### 载荷格式是本库私有的

这是**刻意**的，不是「暂时没做」：信封完全由本库定义 —— 密文里不压手工 HMAC（DB 侧从不校验它），也不留非 AEAD 分支。因此本库只认自己写出的密文：**非本库格式一律读不了**。列里若已有那样的数据，必须在应用侧重新加密迁移。

### `is_encrypted` 是廉价形状判定，会有假阳性

它只做长度闸 + base64 解码 + 版本字节 + 长度下限，**不碰密钥、不做认证**。一段 base64 解出来首字节恰好是格式字节（应用侧 `0x03`/`0x01`、DB 侧 `0x04`/`0x02`）的明文会被判为密文，概率约 2/256 还得是合法 base64。真正需要确定性答案用 `decrypt`（它会真的认证一次）。

同一位面的两道**误拒**闸门也各有上限：`DbEncrypter::encrypt` 会拒绝「长度 ≥ 40 且形状像应用侧载荷」的输入 —— 短于 40 字符的 `AQ…` 类业务码不再误伤（那是曾经的一个硬缺陷），但足够长又恰好吻合的仍会被拦，绕过口是 `seal()`。应用侧的 `encrypt()` 反方向不做拦截（见「密钥分离」上一节）。

顺带一提：`encrypt()` 内部**没有**用形状判定来决定「要不要再加密」—— 它是真的试解一次，正是为了避开「看起来像密文的明文被直接存库、从此解不开」这个坑。

### DB 路径忽略 `previous_keys`

DB 侧密文只认构造时那一把主密钥。轮换 DB 侧密文走的是上层迁移（重写整列），不是密钥环 —— SQL 片段嵌的密钥对它才作数，环上其他钥匙没有意义。配置里带着 `previous_keys` 时 `DbEncrypter::new` 会向 stderr 打一条警告：按应用侧的轮换剧本操作 DB 侧列，SQL 一侧会静默变 NULL（MySQL）或直接报错（pgcrypto）。

### GCM nonce 的生日界

应用侧用 96 位随机 nonce。同一把密钥下，约 2^32 条消息之后 nonce 碰撞的概率就不再可以忽略（碰撞会让 GCM 的认证与机密性同时失效）。这个量级对绝大多数业务够用，但**别把同一把主密钥用在每秒百万次写入的列上而不轮换** —— 轮换正是为此存在的。

### 密文是标准 base64，进 URL 前必须换字母表

密文用的是**标准 base64**，字母表里有 `/` 和 `+`。把它直接放进 URL 路径，`/` 会被当成路径分隔符，请求落到别的路由上 —— 表现为**偶发的 404**，因为出不出 `/` 取决于随机 nonce（约一半的概率）。

要把密文放进 URL（路径或查询串），先换成 base64url 字母表：`+`→`-`、`/`→`_`，收到后换回来。这不是本库的限制，是 URL 的：任何标准 base64 进 URL 都要这么处理。载荷本身通常该放在请求体里，而不是 URL 里。

### 主密钥不做口令拉伸：必须正好是密码要求的长度

主密钥是裸字节，没有盐、没有迭代 —— 它是**高熵随机密钥**，不是口令。（内部的 HKDF 只做用途分离，不是口令拉伸。）所以弱口令不会被「拉伸」成密钥，它会被 `Error::KeyLength` 直接拒绝（32 字节密码配 16 字节密钥同样拒绝）。密钥请用 `encryptable keygen` 生成，不要自己敲。另一个后果是：长度恰好是密码要求**两倍**的 hex 字符串会被当成十六进制解释（256 位密码 64 字符、128 位 32 字符），而不是字面量 —— 这是为了让运维手上能有一份和 SQL 片段里一样的表示，也让 `to_hex()` 的输出能回喂解析器。

---

## 请求周期

![请求周期：HTTP 请求 → 框架路由 → 守卫提取 → 处理器 → 加解密 → 数据库 → 响应](./docs/diagrams/zh-CN/request-lifecycle.svg)

一个请求穿过框架集成层时只发生三件事：

1. **路由**：框架按自己的方式匹配到处理器。
2. **提取**：适配层从框架的状态槽位取 [`Guard`]，克隆一次 `Arc`。axum 路径经 `Guarded` 从状态里取，取不到是编译期就发现的事；其余框架（`app_data` / `manage` / `data` / `Depot` / 请求扩展）运行期可能发现没装配 —— 那会被翻译成 500，消息点名缺了哪一步。
3. **加解密**：处理器拿着 `guard` 做事。密钥环在**启动时**就解析好了，这一路上没有任何一次读环境变量、解析字符串或派生密钥。

值得记住的是**失败发生在哪里**：

| 失败 | 何时 | 谁负责回应 |
|------|------|-----------|
| 状态里没注册守卫 | 提取前（装配阶段漏了） | 适配层 → 500，消息点名缺了哪一步 |
| tag 校验不过 / 环上没有钥匙能解开 | 处理器体内 | **调用方** —— 本库不替应用决定该回 500 还是 422 |
| 密文格式不对（拿应用侧载荷喂 DB 侧） | 处理器体内 | 调用方，且是明确的 `Error::WrongFormat` |

第一行是服务端自己的装配错误，用户没做错任何事，所以是 5xx；后两行是业务语义，必须由应用决定 —— 一个把密文列当普通列读的接口，和一个人工触发的迁移任务，对「解不开」该有完全不同的回应。

---

## 生命周期

![生命周期：值往返、DB 查询的两条路径、密钥轮换四步](./docs/diagrams/zh-CN/lifecycle.svg)

### 应用侧：一次往返

```
写入   明文 / 标量 → Value 类型信封(tag || 载荷) → AES-GCM(随机 nonce,
       AAD = 版本字节 [‖ 上下文], 密钥 = HKDF 子密钥)
       → 0x03 || nonce || 密文 || tag → base64 → 落库
读出   base64 → 版本字节核对(0x03 / 0x01) → 长度下限 → 逐把钥匙试 GCM 认证
       → 任一把成功即解出明文 → Value::decode → 还原成原类型
```

环上是「主密钥在前、退役密钥在后」；每一把钥匙各自的子密钥在构造时就派生好了。刻意**不告诉调用方**是哪把钥匙解开的 —— 把「是第几把」泄出去等于泄了轮换进度。

### DB 侧：查询的两条路径

```
① 等值比对（推荐）   encrypt(输入) → 密文 → 绑定进 WHERE phone = ?
                    代价：应用侧先算一次；好处：密钥不进 SQL，该列的索引可用

② SELECT 列表解密    decrypt_expr("phone", driver) → SQL 片段 → 交给数据库执行
                    代价：主密钥嵌进 SQL 文本，索引失效；好处：不用改查询结构
```

**过滤用 ①、取明文用 ②** —— 反过来用就会同时拿到两份代价。

### 密钥轮换：四步

| 步骤 | 动作 | 此刻的状态 |
|------|------|-----------|
| 1 | 换主密钥：`ENCRYPTION_KEY=<新>` | 新数据用新密钥写入，**存量数据立刻读不出来** |
| 2 | 旧密钥进 `ENCRYPTION_PREVIOUS_KEYS` | 存量恢复可读；新旧密文同时在库里 |
| 3 | 后台任务批量 `rotate_to_current_key()` | 存量逐条搬成新主密钥的密文 |
| 4 | 确认无旧密文后摘掉 `previous_keys` | 轮换完成，`ring_len()` 回到 1 |

第 1、2 步之间可以有间隔，但**必须当成一次变更发布** —— 只做第 1 步等于把全部存量数据变成解不开的字节。第 3 步可以慢慢跑，跑多久都不会丢数据；`rotate_to_current_key()` 对本来就是明文的输入原样返回，所以批处理里可以无脑全表调用。第 4 步之前要确认真的搬完了：`previous_keys` 留着不会报错，只会一直留在环上，下一次轮换时越堆越长。

---

## 使用说明

### 零配置起步（环境变量）

```bash
# 先生成一把密钥，keygen 会把同一把密钥的两种可用写法都打出来（hex 与 base64: 前缀）
encryptable keygen

# 粘其中一行过来即可
export ENCRYPTION_KEY=<那把密钥>
export ENCRYPTION_CIPHER=aes-256-gcm          # 默认值，可省
export ENCRYPTION_PREVIOUS_KEYS=old1,old2     # 逗号分隔；JSON 数组会被拒绝
export ENCRYPTION_DB_DRIVER=mysql             # 或 pgsql / postgres
```

```rust
use encryptable::config::EnvConfig;
use encryptable::AeadEncrypter;

let encrypter = AeadEncrypter::new(&EnvConfig::from_env())?;
```

不用环境变量的写法：

```rust
use encryptable::config::{ArrayConfig, DbDriver};
use encryptable::{AeadEncrypter, DbEncrypter};

// 应用侧 —— 默认路径，所有存储场景都用它
let app = AeadEncrypter::new(&ArrayConfig::new("0123456789abcdef0123456789abcdef"))?;

let c = app.encrypt("13800138000")?;      // 也接受 i64 / f64 / bool —— 见 Value 的 From 实现
let v = app.decrypt(&c)?;                 // -> Value
let s = app.decrypt_text(&c)?;            // -> String
app.is_encrypted(&c);                     // 廉价形状判定，不碰密钥
app.rotate_to_current_key(&c)?;           // 轮换：读旧密钥、写新密钥
app.cipher_name(); app.ring_len();
app.decrypt_or_original("plain");         // 宽松版，显式选择

// 防密文跨行/跨列转移：上下文进 AAD，解的时候必须对得上
let sealed = app.seal_with_context("users/42.phone", "13800138000")?;
app.decrypt_text_with_context("users/42.phone", &sealed)?;
app.decrypt(&sealed).is_err();            // 不带上下文解不开 —— 这是特性

// DB 侧 —— 只给必须按原值查询的列
let db = DbEncrypter::new(
    &ArrayConfig::new("0123456789abcdef0123456789abcdef")
        .with_cipher("aes-256-ecb")
        .with_db_driver(DbDriver::Postgres),
)?;

let bound = db.encrypt("13800138000")?;   // 确定性，可绑进 WHERE
let plain = db.decrypt(&bound)?;          // 迁移 / CLI 用
db.decrypt_expr("phone", DbDriver::Mysql)?;   // 返回 SQL 片段字符串；driver 参数决定方言
db.seal(plaintext_lookalike)?;            // 形状判定误拒长输入时的绕过口
db.is_encrypted(&bound); db.key_hex(); db.derived_key_hex(); db.driver();
```

轮换：

```rust
// 换主密钥，旧的退进 previous_keys —— 存量照读
let rotated = AeadEncrypter::new(
    &ArrayConfig::new("<新主密钥>").with_previous_keys(vec!["<旧主密钥>".into()]),
)?;
rotated.decrypt_text(&old_ciphertext)?;                       // 还读得出来
let moved = rotated.rotate_to_current_key(&old_ciphertext)?;  // 搬到新主密钥
```

### 两条查询配方

```rust
// ① 过滤：先把密文算出来，再当参数绑定（任何驱动都一样）—— 密钥不进 SQL，索引可用
let cipher = db.encrypt(user_input)?;
// SELECT id FROM users WHERE phone = ?      -- 参数即上面的 cipher

// ② 取明文：让数据库自己解 —— 只用在 SELECT 列表
let expr = db.decrypt_expr("phone", DbDriver::Mysql)?;
// SELECT id, <expr> AS phone FROM users WHERE id = ?
```

### CLI

```bash
encryptable keygen                       # 生成一把 32 字节主密钥
encryptable pet                          # 打印项目宠物

C=$(encryptable encrypt 13800138000)     # 应用侧加密
encryptable decrypt "$C"                 # 应用侧解密
encryptable rotate "$C"                  # 用当前主密钥重新加密

D=$(encryptable db-encrypt 13800138000)  # DB 侧确定性加密（ENCRYPTION_CIPHER 需为 aes-256-ecb）
encryptable db-decrypt "$D"              # DB 侧还原（迁移用）
encryptable sql phone --driver mysql     # 打印 SQL 片段
```

密钥只从**环境变量**读，不从 argv 读 —— argv 会通过 `ps` 和 shell 历史泄漏。内容也可以走管道：`printf 13800138000 | encryptable encrypt`。退出码：`0` 成功 · `1` 用法错误 · `2` 配置或密码学错误。

---

## 开发

```bash
cargo build
cargo test
cargo test --features serde
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

默认构建 **181 个测试通过**（另有 1 个默认 `#[ignore]`，它要连真实 MySQL），`--features serde` 是 **187 个**，全特性（含八个框架适配层的测试与文档示例）是 **233 个**。每个框架 feature 各自再带一套适配层测试，只在开启该 feature 时编译：

```bash
cargo test --features axum        # 每个框架一套
cargo test --features actix-web
cargo test --features rocket
cargo test --features poem
cargo test --features salvo
cargo test --features warp
cargo test --features bee-rust
cargo test --features ecat
```

集成测试里有 1 个默认 `#[ignore]` —— 它要连真实 MySQL，默认跳过：

```bash
ENCRYPTION_TEST_MYSQL=mysql://user:pass@localhost/db cargo test --test db_sql -- --ignored
```

正确性锚点有两个：

- **金标量：与独立实现逐字节对齐。** DB 路径的 PKCS#7 + ECB 是手写的，`src/encrypter/db/tests.rs` 里两组金标量把它钉死：当前格式（`0x04`，HKDF 子密钥）由 Python `cryptography` 独立复算、再用 `openssl enc -aes-256-ecb -K <子密钥> -nosalt` 交叉验证；1.2.x 的 `0x02`（主密钥直用）向量转为**双读回归锚** —— 只断言解密，保证旧密文照旧解得开。这是「数据库能不能读懂我们写的字节」唯一能在 CI 里验证的代理 —— 手写补位少补一个块、字节序错一位，这条测试都会红。
- **性质：`tests/invariants.rs`。** 这一层钉的不是字节而是行为 —— 一组不变量：往返恒等、篡改必被拒、错误密钥必被拒、随机 nonce 不重复、DB 路径确定性、两种载荷互不通用。语料用手写 LCG 生成而不引 `proptest` / `quickcheck` —— 确定性、可复现、零依赖。

整条轮换迁移路径（换主密钥 → 旧密钥进环 → 批量搬运 → 摘除）在 `tests/rotation.rs`。

两条路径加一次完整轮换的可运行演示在 `examples/quickstart.rs`：

```bash
cargo run --example quickstart
```

---

## 打赏 / 赞助

如果这个项目对你有帮助，欢迎打赏支持（自愿）。

| 支付宝 | 微信支付 |
|--------|---------|
| ![支付宝](docs/alipay.png) | ![微信支付](docs/weixinpay.png) |

### 全球转账（国际汇款）

【收款人信息】
- 收款人姓名：WANG KEXUN
- 收款账户号码：881015918251

【收款银行】
- ZA Bank SWIFT Code：AABLHKHHXXX
- 银行名称：ZA Bank Limited
- 银行编号：387
- 银行地址：Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

【跨境汇款代理银行（如需）】

请留意，此为跨境汇款代理银行（中转银行）信息，非收款银行信息。请向汇款银行查询是否需要提供跨境汇款代理银行信息。

汇入港元、人民币及美元的代理银行为 Citibank：
- 银行名称：Citibank N.A. Hong Kong
- SWIFT Code：CITIHKHXXXX
- 银行编号：006
- 分行名称：Hong Kong Branch
- 分行编号：391
- 银行地址：Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong

汇入其他币种时的代理银行为 BNY Mellon：
- 银行名称：THE BANK OF NEW YORK MELLON
- SWIFT Code：IRVTUS3NXXX
- 银行地址：THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## 许可

MIT — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
